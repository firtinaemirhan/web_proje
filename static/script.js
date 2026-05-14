// DOM Elements
const dropZone = document.getElementById('drop-zone');
const fileInput = document.getElementById('file-input');
const fileInfo = document.getElementById('file-info');
const filenameSpan = document.getElementById('filename');
const analyzeBtn = document.getElementById('analyze-btn');
const mobsfKeyInput = document.getElementById('mobsf-key');
const vtKeyInput = document.getElementById('vt-key');
const geminiKeyInput = document.getElementById('gemini-key');

// Layout Elements
const emptyState = document.getElementById('empty-state');
const progressContainer = document.getElementById('progress-container');
const resultContainer = document.getElementById('result-container');
const statusText = document.getElementById('status-text');
const taskSidebar = document.getElementById('task-sidebar');
const taskListEl = document.getElementById('task-list');
const queueCountEl = document.getElementById('queue-count');

// State Management
let selectedFiles = []; // Temporary holding for drag/drop before analysis start
const MAX_CONCURRENT_UPLOADS = 1;
let activeUploads = 0;

// Task Store: Map<tempId, { file, status, step, serverTaskId, result, error }>
// Status: pending, running, completed, error
let taskStore = {};
let taskQueue = []; // Array of tempIds
let currentSelectedTaskId = null;

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    loadKeys();
    // Check if we have items (refresh persistence could be added later)
});

// Drag & Drop
dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('drag-over');
});

dropZone.addEventListener('dragleave', () => {
    dropZone.classList.remove('drag-over');
});

dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('drag-over');
    if (e.dataTransfer.files.length > 0) {
        handleFileSelection(e.dataTransfer.files);
    }
});

fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
        handleFileSelection(e.target.files);
    }
});

function handleFileSelection(files) {
    // Filter APKs
    const validFiles = Array.from(files).filter(f => f.name.toLowerCase().endsWith('.apk'));

    if (validFiles.length === 0) {
        alert('Please select valid .apk files.');
        return;
    }

    selectedFiles = validFiles;

    // UI Update for Selection
    document.querySelector('.upload-area').classList.add('hidden');
    fileInfo.classList.remove('hidden');
    filenameSpan.textContent = `${selectedFiles.length} file(s) selected`;
    analyzeBtn.disabled = false;
}

function clearFile() {
    selectedFiles = [];
    fileInput.value = '';
    document.querySelector('.upload-area').classList.remove('hidden');
    fileInfo.classList.add('hidden');
    analyzeBtn.disabled = true;
}

function toggleLLMFields() {
    const provider = document.getElementById('llm-provider').value;
    const ollamaInput = document.getElementById('ollama-model');

    // Reset default state
    ollamaInput.disabled = false;

    if (provider === 'gemini') {
        document.getElementById('gemini-fields').style.display = 'block';
        document.getElementById('ollama-fields').style.display = 'none';
    } else if (provider === 'ollama') {
        document.getElementById('gemini-fields').style.display = 'none';
        document.getElementById('ollama-fields').style.display = 'block';
    } else {
        // Şamdan.ai
        document.getElementById('gemini-fields').style.display = 'none';
        document.getElementById('ollama-fields').style.display = 'block';
        ollamaInput.value = 'samdan-ai';
        ollamaInput.disabled = true;
    }
}

// -------------------------------------------------------------------------
// Bulk Analysis Logic
// -------------------------------------------------------------------------

async function startAnalysis() {
    saveKeys();
    if (selectedFiles.length === 0) return;

    // 1. Switch to Bulk Layout
    const uploadCard = document.querySelector('.upload-card');
    if (uploadCard) uploadCard.classList.add('hidden'); // Hide upload card to focus on queue
    taskSidebar.classList.remove('hidden');
    analyzeBtn.disabled = true; // Prevent double submit
    fileInfo.classList.add('hidden'); // Hide selection info

    // 2. Initialize Tasks
    selectedFiles.forEach(file => {
        const tempId = 'local_' + Math.random().toString(36).substr(2, 9);
        taskStore[tempId] = {
            id: tempId,
            file: file,
            status: 'pending',
            step: 'Queued',
            serverTaskId: null,
            result: null,
            timestamp: new Date().toLocaleTimeString()
        };
        taskQueue.push(tempId);
    });

    // 3. Initial Render & Process
    renderTaskList();
    processQueue();

    // Select the first one automatically
    if (taskQueue.length > 0) {
        selectTask(taskQueue[0]);
    }
}

function processQueue() {
    // While we have slots and items in queue
    while (activeUploads < MAX_CONCURRENT_UPLOADS && taskQueue.length > 0) {
        const nextId = taskQueue.shift();
        activeUploads++;
        uploadTask(nextId);
    }
    updateQueueCount();
}

async function uploadTask(tempId) {
    const task = taskStore[tempId];
    task.status = 'running';
    task.step = 'Uploading...';
    renderTaskItem(tempId); // Update Sidebar status

    // Update Main View if selected
    if (currentSelectedTaskId === tempId) {
        renderMainView(tempId);
    }

    // Prepare API Call
    const formData = new FormData();
    formData.append('file', task.file);
    formData.append('mobsf_key', mobsfKeyInput.value);
    formData.append('vt_key', vtKeyInput.value);

    const provider = document.getElementById('llm-provider').value;
    let modelName = 'gemini-2.5-flash';
    if (provider === 'ollama') modelName = document.getElementById('ollama-model').value;
    if (provider === 'samdan') modelName = 'samdan-ai';

    formData.append('llm_provider', provider);
    formData.append('llm_key', geminiKeyInput.value);
    formData.append('llm_model', modelName);

    try {
        const response = await fetch('/api/upload', {
            method: 'POST',
            body: formData
        });

        if (!response.ok) throw new Error('Upload Failed');

        const data = await response.json();
        task.serverTaskId = data.task_id;
        task.step = 'Initializing Analysis...';

        // Start Polling
        pollTask(tempId, data.task_id);

    } catch (e) {
        console.error(e);
        task.status = 'error';
        task.step = 'Upload Failed';
        activeUploads--;
        renderTaskItem(tempId);
        if (currentSelectedTaskId === tempId) renderMainView(tempId);
        processQueue(); // Release slot
    }
}

async function pollTask(tempId, serverTaskId) {
    const task = taskStore[tempId];

    const interval = setInterval(async () => {
        try {
            const response = await fetch(`/api/status/${serverTaskId}`);
            if (!response.ok) return; // Wait for next tick

            const data = await response.json();
            task.step = data.step;

            // UI Updates
            renderTaskItem(tempId);
            if (currentSelectedTaskId === tempId) {
                updateStepper(task.step);
                document.getElementById('status-text').textContent = task.step;
            }

            if (data.status === 'completed') {
                clearInterval(interval);
                fetchResults(tempId, serverTaskId);
            } else if (data.status === 'failed') {
                clearInterval(interval);
                task.status = 'error';
                task.result = { error: data.error };
                task.step = 'Analysis Failed'; // Fix step text
                finishTask(tempId);
            }

        } catch (e) {
            console.error("Polling error", e);
        }
    }, 2000);
}

async function fetchResults(tempId, serverTaskId) {
    try {
        const response = await fetch(`/api/result/${serverTaskId}`);
        const data = await response.json();
        const task = taskStore[tempId];

        task.status = 'completed';
        task.result = data;
        task.step = 'Done';

        finishTask(tempId);

    } catch (e) {
        taskStore[tempId].status = 'error';
        finishTask(tempId);
    }
}

function finishTask(tempId) {
    activeUploads--;
    renderTaskItem(tempId);
    if (currentSelectedTaskId === tempId) renderMainView(tempId);
    processQueue(); // Trigger next
}

// -------------------------------------------------------------------------
// UI Rendering
// -------------------------------------------------------------------------

function updateQueueCount() {
    queueCountEl.textContent = taskQueue.length + activeUploads;
}

function renderTaskList() {
    taskListEl.innerHTML = ''; // Clear
    Object.values(taskStore).forEach(task => {
        const li = document.createElement('li');
        li.className = `task-item ${currentSelectedTaskId === task.id ? 'active' : ''}`;
        li.id = `task-item-${task.id}`;
        li.onclick = () => selectTask(task.id);

        li.innerHTML = `
            <div class="task-info">
                <div class="filename" title="${task.file.name}">${task.file.name}</div>
                <div style="font-size:0.75rem; color:#999">${task.step}</div>
            </div>
            <div class="status-icon ${getStatusClass(task.status)}">
                ${getStatusIcon(task.status)}
            </div>
        `;
        taskListEl.appendChild(li);
    });
}

function renderTaskItem(tempId) {
    // Optimized update for single item
    const task = taskStore[tempId];
    const li = document.getElementById(`task-item-${tempId}`);
    if (li) {
        li.querySelector('.filename').nextElementSibling.textContent = task.step;
        const iconContainer = li.querySelector('.status-icon');
        iconContainer.className = `status-icon ${getStatusClass(task.status)}`;
        iconContainer.innerHTML = getStatusIcon(task.status);
    }
}

function getStatusClass(status) {
    if (status === 'pending') return 'pending';
    if (status === 'running') return 'running';
    if (status === 'completed') return 'success';
    if (status === 'error') return 'error';
    return '';
}

function getStatusIcon(status) {
    if (status === 'pending') return '<i class="uil uil-clock"></i>';
    if (status === 'running') return '<i class="uil uil-sync"></i>';
    if (status === 'completed') return '<i class="uil uil-check-circle"></i>';
    if (status === 'error') return '<i class="uil uil-exclamation-triangle"></i>';
    return '';
}

function selectTask(tempId) {
    currentSelectedTaskId = tempId;

    // Highlight in sidebar
    document.querySelectorAll('.task-item').forEach(el => el.classList.remove('active'));
    const li = document.getElementById(`task-item-${tempId}`);
    if (li) li.classList.add('active');

    renderMainView(tempId);
}

function renderMainView(tempId) {
    const task = taskStore[tempId];
    if (!task) return;

    // Show Details Container
    emptyState.classList.add('hidden');

    // Set Header Info
    document.getElementById('current-analyzing-file').textContent = task.file.name;
    document.getElementById('result-filename').textContent = task.file.name;
    document.getElementById('result-timestamp').textContent = task.timestamp;

    if (task.status === 'pending' || task.status === 'running') {
        progressContainer.classList.remove('hidden');
        resultContainer.classList.add('hidden');
        document.getElementById('status-text').textContent = task.step;
        updateStepper(task.step);
    }
    else if (task.status === 'completed' && task.result) {
        progressContainer.classList.add('hidden');
        resultContainer.classList.remove('hidden');
        renderResultData(task.result);
    }
    else if (task.status === 'error') {
        progressContainer.classList.add('hidden');
        resultContainer.classList.remove('hidden'); // Reuse result container for error?
        // Or just show alert? Better to show error in raw tab
        document.getElementById('ai-output').innerHTML = `<div style="color:red; padding:20px;">Analysis Failed: ${task.result?.error || 'Unknown Error'}</div>`;
        document.getElementById('raw-json').textContent = JSON.stringify(task, null, 2);
    }
}

function renderResultData(data) {
    // Render AI Markdown
    const aiText = data.ai_analysis || "No AI analysis available.";
    document.getElementById('ai-output').innerHTML = marked.parse(aiText);

    // Render Raw JSON
    document.getElementById('raw-json').textContent = JSON.stringify(data, null, 2);

    // Determine Verdict Banner
    const verdictBanner = document.getElementById('verdict-banner');
    const verdictLabel = document.getElementById('verdict-label');
    const upperText = aiText.toUpperCase();

    const isMalicious = upperText.includes('VERDICT: MALICIOUS') || upperText.includes('**MALICIOUS**');
    const isSuspicious = upperText.includes('VERDICT: SUSPICIOUS') || upperText.includes('**SUSPICIOUS**');
    const isBenign = upperText.includes('VERDICT: BENIGN') || upperText.includes('**BENIGN**');

    verdictBanner.className = 'verdict-banner';
    verdictBanner.style = '';

    if (isMalicious) {
        verdictBanner.classList.add('malware');
        verdictLabel.textContent = 'DETECTED: MALICIOUS';
    } else if (isSuspicious) {
        verdictBanner.classList.add('unknown');
        verdictBanner.style.borderColor = '#f59e0b';
        verdictBanner.style.color = '#f59e0b';
        verdictBanner.style.background = 'rgba(245, 158, 11, 0.1)';
        verdictLabel.textContent = 'WARNING: SUSPICIOUS';
    } else if (isBenign) {
        verdictBanner.classList.add('safe');
        verdictLabel.textContent = 'CLEAN: BENIGN';
    } else {
        verdictBanner.classList.add('unknown');
        verdictLabel.textContent = 'VERDICT: UNKNOWN';
    }
}

// Helpers
function updateStepper(stepText) {
    if (!stepText) return;
    document.querySelectorAll('.step').forEach(s => s.classList.remove('active'));
    let activeIndex = 1;
    if (stepText.includes('MobSF')) activeIndex = 2;
    if (stepText.includes('Subfinder') || stepText.includes('Network')) activeIndex = 3;
    if (stepText.includes('VirusTotal')) activeIndex = 4;
    if (stepText.includes('AI') || stepText.includes('Consulting')) activeIndex = 5;
    if (stepText.includes('Done')) activeIndex = 6;

    for (let i = 1; i <= 5; i++) {
        const stepEl = document.getElementById(`step-${i}`);
        if (i <= activeIndex) stepEl.classList.add('active');
    }
}

function switchTab(tab) {
    // jQuery ile yumuşak geçiş efektli (fadeIn) ve bug-fixli tab geçişi
    $('.sc-tab').removeClass('active');
    $('.tab-content').hide().removeClass('active'); // fade öncesi gizle

    $(`.sc-tab[onclick="switchTab('${tab}')"]`).addClass('active');
    
    // Geçiş yapılacak tab'i yumuşak biçimde görünür yap
    $(`#tab-${tab}`).fadeIn(200, function() {
        $(this).addClass('active');
    });
}

// -------------------------------------------------------------------------
// JQUERY FONKSİYONEL EKLENTİLER (UX / UI YENİLİKLERİ)
// -------------------------------------------------------------------------
$(document).ready(function() {
    // 1. Akordeon Özelliği: Kart başlıklarına tıklayınca içerikleri yavaşça aç/kapat (örneğin ayarlar bölümü gizlenebilsin)
    $('.sc-card-header').css({
        'cursor': 'pointer',
        'user-select': 'none',
        'transition': 'opacity 0.2s'
    }).hover(
        function() { $(this).css('opacity', '0.8'); },
        function() { $(this).css('opacity', '1'); }
    ).click(function() {
        $(this).next('.sc-card-body').slideToggle(300);
        const icon = $(this).find('i').first();
        // Basit animasyonla ikon yönünü çevirmesi için class taklası yapalım (rotate var ise)
        icon.toggleClass('rotated');
    });

    // 2. Alert/Toast Efekti: Analiz Raporunu indirildiğinde ekranda beliren geçici bir bildirim (İndir butonuna tıklanınca)
    $('.sc-icon-btn[title="Rapor İndir"]').on('click', function() {
        // İndirme işlemi tetiklendiğinde hafif bir parlatma (pulse) efekti
        $(this).fadeOut(100).fadeIn(100).fadeOut(100).fadeIn(100);
    });
});

function resetApp() {
    // In bulk mode, reset might mean clearing selection or reloading
    location.reload();
}

// LocalStorage helpers
function saveKeys() {
    localStorage.setItem('mobsf_key', mobsfKeyInput.value);
    localStorage.setItem('vt_key', vtKeyInput.value);
    localStorage.setItem('gemini_key', geminiKeyInput.value);
    localStorage.setItem('llm_provider', document.getElementById('llm-provider').value);
    localStorage.setItem('ollama_model', document.getElementById('ollama-model').value);
}

function loadKeys() {
    if (localStorage.getItem('mobsf_key')) mobsfKeyInput.value = localStorage.getItem('mobsf_key');
    if (localStorage.getItem('vt_key')) vtKeyInput.value = localStorage.getItem('vt_key');
    if (localStorage.getItem('gemini_key')) geminiKeyInput.value = localStorage.getItem('gemini_key');

    if (localStorage.getItem('llm_provider')) {
        document.getElementById('llm-provider').value = localStorage.getItem('llm_provider');
        toggleLLMFields();
    }

    if (localStorage.getItem('ollama_model')) document.getElementById('ollama-model').value = localStorage.getItem('ollama_model');
}

// Export Logic
async function downloadReport() {
    const completedTaskIds = Object.values(taskStore)
        .filter(t => t.status === 'completed')
        .map(t => t.serverTaskId);

    if (completedTaskIds.length === 0) {
        alert("No completed analyses to export.");
        return;
    }

    try {
        const response = await fetch('/api/export_report', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ task_ids: completedTaskIds })
        });

        if (!response.ok) throw new Error("Export failed");

        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `Analysis_Report_${new Date().toISOString().slice(0, 10)}.xlsx`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        a.remove();

    } catch (e) {
        console.error("Export Error:", e);
        alert("Failed to generate export file.");
    }
}


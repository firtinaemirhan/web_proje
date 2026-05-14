import re
import json

appsec_data = {
  "high": [
    {
      "title": "Insecure Implementation of SSL...",
      "description": "Insecure Implementation of SSL. Trusting all the certificates or accepting self signed certificates is a critical Security Hole. This application is vulnerable to MITM attacks\nhttps://github.com/MobSF/owasp-mstg/blob/master/Document/0x05g-Testing-Network-Communication.md#android-network-apis\n\nFiles:\ncom/common/sendlog/util/OtherUtils.java, line(s) 220,220,15,16,17,18,19\ncom/lidroid/xutils/http/client/DefaultSSLSocketFactory.java, line(s) 61,13,14,15\ncom/lidroid/xutils/util/OtherUtils.java, line(s) 222,222,15,16,17,18,19",
      "section": "code"
    },
     {
      "title": "The file or SharedPreference is World Readable.",
      "description": "The file or SharedPreference is World Readable. Any App can read from the file\nhttps://github.com/MobSF/owasp-mstg/blob/master/Document/0x05d-Testing-Data-Storage.md#testing-local-storage-for-sensitive-data-mstg-storage-1-and-mstg-storage-2\n\nFiles:\nauda/sndnv/uens/utils/b.java, line(s) 14",
      "section": "code"
    }
  ],
  "warning": []
}

suspicious_files = set()
for category in ['high', 'warning']:
     for finding in appsec_data.get(category, []):
         description = finding.get('description', '')
         # The regex used in app.py
         found_paths = re.findall(r'[\w/\\.]+\.java', description)
         
         print(f"--> Scanning description: '{description[:30]}...'")
         print(f"    Found raw matches: {found_paths}")
         
         for p in found_paths:
             p = p.strip().replace('\\', '/')
             suspicious_files.add(p)

print(f"\nFinal Suspicious Files Set: {suspicious_files}")

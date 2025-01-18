# FDU_JWFW_Checker

## A jwfw.fudan.edu.cn checker that can inform you the newest update of your grades
## Refer to https://github.com/Boreas618/FDU-Grade-Checker
## Guide
1. FORK this repository;
2. Add your secrets to Settings-Secrets and variables-Actions-New repository secrets:
        STD_ID = student ID,
        PASSWORD = UIS password,
        TOKEN = up to you but never lack it,
        SENDER = sender's email address, only support QQ mail,
        SENDER_PWD = sender's email authentication code **(授權碼而非密碼)**
        RECEIVER = receiver's email address;
3. Settings-Actions-General: Allow all actions and reusable workflows; 
4. Settings-Actions-General: Workflow permissions-Read and write permissions
5. Actions-I understand my workflows, go ahead and enable them;
6. Actions-FDU_JWFW Checker-enable workflow;
7. The workflow would run automatically every 5 mins

**Thanks to Boreas618/FDU-Grade-Checker** 
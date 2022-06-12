# CoinjetAuth
## How to run
### Local
You need to run following commands:
```
source venv/bin/activate #Ran automatically by PyCharm
source local_env.sh
uvicorn app.app:app --host 0.0.0.0 --port 8000 #--reload
```
### Production
Automatically deployed by Github CI/CD (still in progress).

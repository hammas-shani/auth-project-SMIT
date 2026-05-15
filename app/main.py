from fastapi import FastAPI
from app.routes import auth

app = FastAPI()
app.include_router(auth.router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="localhost", port=8000)
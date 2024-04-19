from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from decouple import config

from controllers import register, login, index, adm_route

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

#routes
app.include_router(register)
app.include_router(login)
app.include_router(index)
app.include_router(adm_route)

#runs the api
if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host='0.0.0.0',
        port=int(config("port")),
        reload=1,
        server_header=0
    )
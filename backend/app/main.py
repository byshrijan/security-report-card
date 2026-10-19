from fastapi import FastAPI

app = FastAPI(title="Security Report Card API")


@app.get("/api/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}

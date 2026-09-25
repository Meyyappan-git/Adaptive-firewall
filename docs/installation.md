# Installation Guide

## Prerequisites

### Hardware & OS
- **OS**: macOS (Tested on Sonoma/Sequoia) or Linux.
- **RAM**: Minimum 4GB.

### Software
- **Python 3.11+**: Required for backend services.
- **Node.js 18+ & npm**: Required for the Next.js dashboard.

---

## Step-by-Step Setup

### 1. Backend Installation
```bash
# Clone the repository (if applicable) or navigate to the project root
cd "Adaptive FireWall"

# Create a virtual environment to isolate dependencies
python3 -m venv venv

# Activate the environment
source venv/bin/activate

# Install Python packages
pip install -r backend/requirements.txt
```

### 2. Frontend Installation
```bash
# Open a new terminal window
cd "Adaptive FireWall/frontend"

# Install Node dependencies
npm install
```

### 3. Launching the System
To run the full system, you need two terminal windows:

**Terminal 1 (Backend):**
```bash
source venv/bin/activate
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
```

**Terminal 2 (Frontend):**
```bash
cd frontend
npm run dev
```

### 4. Verification
1. Visit `http://localhost:3000`.
2. Check the **System Health** section on the dashboard.
3. It should show `Backend API: HEALTHY` and `Monitoring: ACTIVE`.

---

## Troubleshooting

- **Port 8000 already in use**: 
  Run `lsof -i :8000` to find the PID and `kill -9 <PID>` to free the port.
- **Database Errors**: 
  The system uses SQLite. If the database becomes corrupted during testing, delete `data/database/firewall.db` and restart the backend to regenerate it.
- **Frontend API Errors**: 
  Ensure the backend is started *before* the frontend. Check that the backend is running at `http://localhost:8000`.

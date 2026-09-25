# Technology Stack

This project utilizes a modern, open-source stack chosen for reliability, performance, and academic transparency.

## 🛠️ Backend (Python Ecosystem)

| Tool | Purpose | Why Chosen | License |
| :--- | :--- | :--- | :--- |
| **Python 3.12** | Core Language | Industry standard for cybersecurity and ML. | PSF License |
| **FastAPI** | Web Framework | High performance, automatic OpenAPI docs, and native async support. | MIT |
| **SQLAlchemy** | ORM | Abstracts database queries, allowing easy migration from SQLite to PostgreSQL. | MIT |
| **SQLite** | Database | Zero-configuration, file-based storage perfect for local academic demos. | Public Domain |
| **Uvicorn** | ASGI Server | Lightning-fast server for running FastAPI applications. | BSD-3 |
| **Pydantic** | Validation | Ensures strict data types for API requests and configuration. | MIT |

## 🎨 Frontend (JavaScript/TypeScript Ecosystem)

| Tool | Purpose | Why Chosen | License |
| :--- | :--- | :--- | :--- |
| **Next.js** | Framework | Provides optimized routing and server-side rendering for a snappy UI. | MIT |
| **React** | UI Library | Component-based architecture for a modular, maintainable dashboard. | MIT |
| **TypeScript** | Type Safety | Prevents runtime errors in complex API data mappings. | Apache 2.0 |
| **Tailwind CSS** | Styling | Utility-first CSS for a professional, consistent "SOC" aesthetic. | MIT |
| **Recharts** | Visualization | Lightweight, responsive charts for real-time traffic monitoring. | MIT |
| **Lucide React** | Iconography | Clean, consistent security-themed iconography. | ISC |

## 🧠 Data & Machine Learning

| Tool | Purpose | Why Chosen | License |
| :--- | :--- | :--- | :--- |
| **scikit-learn** | ML Algorithms | Provided the `IsolationForest` for unsupervised anomaly detection. | BSD-3 |
| **NumPy** | Numerical Computing | Efficient array manipulation for feature scaling. | BSD-3 |
| **Pandas** | Data Analysis | Used for managing traffic dataframes during ML training. | BSD-3 |
| **psutil** | System Monitoring | Access to system-level network and process statistics. | BSD-3 |
| **joblib** | Model Persistence | Efficiently saves and loads trained ML models to disk. | BSD-3 |

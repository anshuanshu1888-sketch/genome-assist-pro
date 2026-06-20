from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from typing import Optional, List
import sqlite3
import hashlib
import datetime
from jose import jwt, JWTError

# ─────────────────────────────────────────────
#  CONFIG
# ─────────────────────────────────────────────
SECRET_KEY = "change_this_in_production"
ALGORITHM  = "HS256"
DB         = "genomed.db"

app    = FastAPI(title="Genomed Assist Pro", version="2.0")
bearer = HTTPBearer()


# ─────────────────────────────────────────────
#  DATABASE
# ─────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB, check_same_thread=False)
    conn.row_factory = sqlite3.Row          # rows behave like dicts
    return conn


def init_db():
    conn = get_db()
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS doctors (
            username       TEXT PRIMARY KEY,
            password       TEXT NOT NULL,
            name           TEXT NOT NULL,
            specialization TEXT NOT NULL,
            created_at     TEXT DEFAULT (datetime('now'))
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS patients (
            id         TEXT PRIMARY KEY,
            name       TEXT NOT NULL,
            age        INTEGER NOT NULL,
            gender     TEXT,
            phone      TEXT,
            diagnosis  TEXT,
            doctor_id  TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (doctor_id) REFERENCES doctors(username)
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS appointments (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id  TEXT NOT NULL,
            doctor_id   TEXT NOT NULL,
            date        TEXT NOT NULL,
            time        TEXT NOT NULL,
            notes       TEXT,
            status      TEXT DEFAULT 'scheduled',
            FOREIGN KEY (patient_id) REFERENCES patients(id),
            FOREIGN KEY (doctor_id)  REFERENCES doctors(username)
        )
    """)

    conn.commit()
    conn.close()


init_db()


# ─────────────────────────────────────────────
#  SECURITY
# ─────────────────────────────────────────────
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def create_token(username: str) -> str:
    payload = {
        "sub": username,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=8),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer)) -> str:
    """Decode JWT and return username, or raise 401."""
    try:
        payload  = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")
        return username
    except JWTError:
        raise HTTPException(status_code=401, detail="Token expired or invalid")


# ─────────────────────────────────────────────
#  PYDANTIC MODELS
# ─────────────────────────────────────────────
class DoctorRegister(BaseModel):
    username:       str = Field(..., min_length=3)
    password:       str = Field(..., min_length=6)
    name:           str
    specialization: str

    model_config = {
        "json_schema_extra": {
            "example": {
                "username": "dr_smith",
                "password": "secret123",
                "name": "Dr. John Smith",
                "specialization": "Cardiology",
            }
        }
    }


class Login(BaseModel):
    username: str
    password: str

    model_config = {
        "json_schema_extra": {
            "example": {"username": "dr_smith", "password": "secret123"}
        }
    }


class PatientCreate(BaseModel):
    id:        str
    name:      str
    age:       int = Field(..., gt=0, lt=150)
    gender:    Optional[str] = None
    phone:     Optional[str] = None
    diagnosis: Optional[str] = None

    model_config = {
        "json_schema_extra": {
            "example": {
                "id": "P001",
                "name": "Alice Johnson",
                "age": 34,
                "gender": "Female",
                "phone": "+1-555-0100",
                "diagnosis": "Hypertension",
            }
        }
    }


class AppointmentCreate(BaseModel):
    patient_id: str
    date:       str
    time:       str
    notes:      Optional[str] = None

    model_config = {
        "json_schema_extra": {
            "example": {
                "patient_id": "P001",
                "date": "2025-08-01",
                "time": "10:30",
                "notes": "Follow-up visit",
            }
        }
    }


class AppointmentUpdate(BaseModel):
    status: str   # scheduled | completed | cancelled

    model_config = {
        "json_schema_extra": {"example": {"status": "completed"}}
    }


# ─────────────────────────────────────────────
#  ROOT
# ─────────────────────────────────────────────
@app.get("/", tags=["General"])
def home():
    return {"status": "Genomed Assist Pro v2.0 Running ✅"}


# ─────────────────────────────────────────────
#  DOCTOR ROUTES
# ─────────────────────────────────────────────
@app.post("/doctor/register", tags=["Doctors"], status_code=201)
def register_doctor(doc: DoctorRegister):
    conn = get_db()
    c    = conn.cursor()

    if c.execute("SELECT 1 FROM doctors WHERE username=?", (doc.username,)).fetchone():
        conn.close()
        raise HTTPException(status_code=409, detail="Doctor already exists")

    c.execute(
        "INSERT INTO doctors (username, password, name, specialization) VALUES (?,?,?,?)",
        (doc.username, hash_password(doc.password), doc.name, doc.specialization),
    )
    conn.commit()
    conn.close()
    return {"message": f"Doctor '{doc.name}' registered successfully"}


@app.post("/doctor/login", tags=["Doctors"])
def login_doctor(data: Login):
    conn = get_db()
    c    = conn.cursor()
    row  = c.execute("SELECT password, name FROM doctors WHERE username=?", (data.username,)).fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Username not found")
    if row["password"] != hash_password(data.password):
        raise HTTPException(status_code=401, detail="Wrong password")

    return {
        "message": f"Welcome back, {row['name']}!",
        "token":   create_token(data.username),
    }


@app.get("/doctor/profile", tags=["Doctors"])
def doctor_profile(username: str = Depends(get_current_user)):
    conn = get_db()
    row  = conn.execute(
        "SELECT username, name, specialization, created_at FROM doctors WHERE username=?",
        (username,),
    ).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Doctor not found")
    return dict(row)


@app.get("/doctor/my-patients", tags=["Doctors"])
def my_patients(username: str = Depends(get_current_user)):
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM patients WHERE doctor_id=?", (username,)
    ).fetchall()
    conn.close()
    return {"patients": [dict(r) for r in rows]}


# ─────────────────────────────────────────────
#  PATIENT ROUTES
# ─────────────────────────────────────────────
@app.post("/patient/add", tags=["Patients"], status_code=201)
def add_patient(patient: PatientCreate, username: str = Depends(get_current_user)):
    conn = get_db()
    conn.execute(
        """INSERT OR REPLACE INTO patients
           (id, name, age, gender, phone, diagnosis, doctor_id)
           VALUES (?,?,?,?,?,?,?)""",
        (patient.id, patient.name, patient.age,
         patient.gender, patient.phone, patient.diagnosis, username),
    )
    conn.commit()
    conn.close()
    return {"message": f"Patient '{patient.name}' saved successfully"}


@app.get("/patients", tags=["Patients"])
def list_patients(username: str = Depends(get_current_user)):
    conn = get_db()
    rows = conn.execute("SELECT * FROM patients").fetchall()
    conn.close()
    return {"total": len(rows), "patients": [dict(r) for r in rows]}


@app.get("/patient/{patient_id}", tags=["Patients"])
def get_patient(patient_id: str, username: str = Depends(get_current_user)):
    conn = get_db()
    row  = conn.execute("SELECT * FROM patients WHERE id=?", (patient_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Patient not found")
    return dict(row)


@app.delete("/patient/{patient_id}", tags=["Patients"])
def delete_patient(patient_id: str, username: str = Depends(get_current_user)):
    conn = get_db()
    cur  = conn.execute("DELETE FROM patients WHERE id=?", (patient_id,))
    conn.commit()
    conn.close()
    if cur.rowcount == 0:
        raise HTTPException(status_code=404, detail="Patient not found")
    return {"message": "Patient deleted"}


# ─────────────────────────────────────────────
#  APPOINTMENT ROUTES
# ─────────────────────────────────────────────
@app.post("/appointment/book", tags=["Appointments"], status_code=201)
def book_appointment(appt: AppointmentCreate, username: str = Depends(get_current_user)):
    conn = get_db()

    # Verify patient exists
    if not conn.execute("SELECT 1 FROM patients WHERE id=?", (appt.patient_id,)).fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="Patient not found")

    conn.execute(
        "INSERT INTO appointments (patient_id, doctor_id, date, time, notes) VALUES (?,?,?,?,?)",
        (appt.patient_id, username, appt.date, appt.time, appt.notes),
    )
    conn.commit()
    conn.close()
    return {"message": "Appointment booked successfully"}


@app.get("/appointments", tags=["Appointments"])
def list_appointments(username: str = Depends(get_current_user)):
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM appointments WHERE doctor_id=? ORDER BY date, time",
        (username,),
    ).fetchall()
    conn.close()
    return {"total": len(rows), "appointments": [dict(r) for r in rows]}


@app.put("/appointment/{appt_id}", tags=["Appointments"])
def update_appointment(
    appt_id: int,
    body: AppointmentUpdate,
    username: str = Depends(get_current_user),
):
    allowed = {"scheduled", "completed", "cancelled"}
    if body.status not in allowed:
        raise HTTPException(status_code=400, detail=f"Status must be one of {allowed}")

    conn = get_db()
    cur  = conn.execute(
        "UPDATE appointments SET status=? WHERE id=? AND doctor_id=?",
        (body.status, appt_id, username),
    )
    conn.commit()
    conn.close()
    if cur.rowcount == 0:
        raise HTTPException(status_code=404, detail="Appointment not found")
    return {"message": f"Appointment {appt_id} marked as '{body.status}'"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

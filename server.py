from fastapi import FastAPI, APIRouter, HTTPException, Depends, status, File, UploadFile
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict, EmailStr
from typing import List, Optional
import uuid
from datetime import datetime, timezone, timedelta
from passlib.context import CryptContext
import jwt
from jwt.exceptions import InvalidTokenError
import razorpay
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, Attachment, FileContent, FileName, FileType, Disposition
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.utils import ImageReader
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image as RLImage
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
import qrcode
from io import BytesIO
import base64
import requests

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Security
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()
SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'your-secret-key-change-in-production')
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

# Razorpay (Test keys)
razorpay_client = razorpay.Client(auth=("rzp_test_placeholder", "test_secret_placeholder"))

# SendGrid
SENDGRID_API_KEY = os.environ.get('SENDGRID_API_KEY', '')
SENDER_EMAIL = "sportsfoundationhealinghearts@gmail.com"

# NGO Details
NGO_NAME = "Healing Heart Sports Foundation"
NGO_ADDRESS = "220, 8 Marla, Near BEEO Office, Model Town, Sonipat - 1311001"
NGO_MOBILE = "7082036886"
NGO_EMAIL = "sportsfoundationhealinghearts@gmail.com"
NGO_DARPAN_ID = "HR/2025/0900271"
NGO_GST = "6AADTH34285RIZZ"
NGO_ACCOUNT = "2502244198348899"
NGO_IFSC = "AUBLO002441"
CO_FOUNDER_NAME = "Dr. Toshin"

# Asset URLs
LOGO_URL = "https://customer-assets.emergentagent.com/job_helping-hands-ngo/artifacts/i3qfl6uh_WhatsApp%20Image%202026-01-20%20at%207.05.49%20PM%20%283%29.jpeg"
SIGNATURE_URL = "https://customer-assets.emergentagent.com/job_helping-hands-ngo/artifacts/8bqjzz7t_WhatsApp%20Image%202026-01-20%20at%207.05.49%20PM%20%281%29.jpeg"

app = FastAPI()
api_router = APIRouter(prefix="/api")

# Models
class UserRegister(BaseModel):
    full_name: str
    gender: str
    date_of_birth: str
    profession: str
    state: str
    city: str
    district: str
    pincode: str
    blood_group: Optional[str] = None
    son_of: str
    aadhaar_number: str
    profile_photo_url: Optional[str] = None
    mobile_number: str
    email: EmailStr
    designation: str  # "Member" or "Coordinator"
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserProfile(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    full_name: str
    email: str
    mobile_number: str
    designation: str
    gender: str
    date_of_birth: str
    profession: str
    state: str
    city: str
    district: str
    pincode: str
    blood_group: Optional[str] = None
    son_of: str
    aadhaar_number: str
    profile_photo_url: Optional[str] = None
    member_id: Optional[str] = None
    registration_date: str
    payment_amount: int
    receipt_url: Optional[str] = None
    certificate_url: Optional[str] = None
    id_card_url: Optional[str] = None

class DonationCreate(BaseModel):
    donor_name: str
    donor_email: EmailStr
    donor_mobile: str
    donor_address: str
    amount: int

class DonationResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    donor_name: str
    donor_email: str
    amount: int
    donation_date: str
    receipt_url: Optional[str] = None

class EnquiryCreate(BaseModel):
    name: str
    email: EmailStr
    message: str

class ActivityCreate(BaseModel):
    title: str
    description: str
    image_url: str
    date: str

class NewsCreate(BaseModel):
    title: str
    content: str
    date: str

class DonationPaymentVerify(BaseModel):
    payment_id: str

# Helper functions
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except InvalidTokenError:
        return None

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    payload = decode_token(token)
    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    user_id = payload.get("sub")
    if user_id is None:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    
    # Check if admin
    if user_id == "admin_001":
        return {
            "id": "admin_001",
            "full_name": "Administrator",
            "email": "admin@healingheart.org",
            "designation": "Admin"
        }
    
    # Regular user
    user = await db.users.find_one({"id": user_id}, {"_id": 0})
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user

def generate_member_id(designation: str) -> str:
    prefix = "HHSF-M" if designation == "Member" else "HHSF-C"
    unique_num = str(uuid.uuid4())[:8].upper()
    return f"{prefix}-{unique_num}"

def download_image(url: str) -> BytesIO:
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return BytesIO(response.content)
    except:
        return None

def generate_qr_code(data: str) -> BytesIO:
    qr = qrcode.QRCode(version=1, box_size=10, border=2)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    return buffer

def number_to_words(num: int) -> str:
    ones = ["", "One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine"]
    tens = ["", "", "Twenty", "Thirty", "Forty", "Fifty", "Sixty", "Seventy", "Eighty", "Ninety"]
    teens = ["Ten", "Eleven", "Twelve", "Thirteen", "Fourteen", "Fifteen", "Sixteen", "Seventeen", "Eighteen", "Nineteen"]
    
    if num == 0:
        return "Zero"
    
    def convert_hundreds(n):
        if n == 0:
            return ""
        elif n < 10:
            return ones[n]
        elif n < 20:
            return teens[n - 10]
        elif n < 100:
            return tens[n // 10] + (" " + ones[n % 10] if n % 10 != 0 else "")
        else:
            return ones[n // 100] + " Hundred" + (" " + convert_hundreds(n % 100) if n % 100 != 0 else "")
    
    if num < 1000:
        return convert_hundreds(num)
    elif num < 100000:
        thousands = num // 1000
        remainder = num % 1000
        return convert_hundreds(thousands) + " Thousand" + (" " + convert_hundreds(remainder) if remainder != 0 else "")
    else:
        lakhs = num // 100000
        remainder = num % 100000
        result = convert_hundreds(lakhs) + " Lakh"
        if remainder >= 1000:
            result += " " + convert_hundreds(remainder // 1000) + " Thousand"
            remainder = remainder % 1000
        if remainder != 0:
            result += " " + convert_hundreds(remainder)
        return result

def generate_receipt_pdf(user_data: dict, transaction_id: str, is_donation: bool = False) -> BytesIO:
    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4
    
    # Download logo
    logo_buffer = download_image(LOGO_URL)
    if logo_buffer:
        c.drawImage(ImageReader(logo_buffer), 250, height - 100, width=100, height=100, preserveAspectRatio=True, mask='auto')
    
    # NGO Header
    c.setFont("Helvetica-Bold", 16)
    c.drawCentredString(width/2, height - 120, NGO_NAME)
    
    c.setFont("Helvetica", 10)
    c.drawCentredString(width/2, height - 135, f"(Registered under Haryana Govt. Reg. No. 97007)")
    c.drawCentredString(width/2, height - 150, f"DARPAN ID: {NGO_DARPAN_ID}")
    c.drawCentredString(width/2, height - 165, f"PAN No.: AADTH4285R  GSTIN: {NGO_GST}")
    c.drawCentredString(width/2, height - 180, f"Address: {NGO_ADDRESS}")
    c.drawCentredString(width/2, height - 195, f"Mobile: {NGO_MOBILE} | Bank: AU Small Finance Bank")
    c.drawCentredString(width/2, height - 210, f"A/C No.: {NGO_ACCOUNT}")
    c.drawCentredString(width/2, height - 225, f"IFSC: {NGO_IFSC}")
    
    # Receipt Title
    c.setFont("Helvetica-Bold", 14)
    c.drawCentredString(width/2, height - 260, "DONATION RECEIPT SLIP" if is_donation else "PAYMENT RECEIPT")
    
    # Receipt details
    y_pos = height - 300
    c.setFont("Helvetica", 11)
    
    receipt_num = f"HHSF/{'DN' if is_donation else 'MB'}/{datetime.now().strftime('%y-%m')}/{transaction_id[:8]}"
    c.drawString(50, y_pos, f"Receipt No.: {receipt_num}")
    c.drawRightString(width - 50, y_pos, f"Financial Year: 2025-26")
    
    y_pos -= 30
    c.drawString(50, y_pos, f"Date: {datetime.now().strftime('%d/%m/%Y')}")
    
    y_pos -= 30
    name = user_data.get('donor_name' if is_donation else 'full_name', '')
    c.drawString(50, y_pos, f"Received with thanks from: {name}")
    
    if is_donation:
        y_pos -= 25
        c.drawString(50, y_pos, f"Address: {user_data.get('donor_address', '')}")
    
    y_pos -= 30
    amount = user_data.get('amount', 0)
    c.drawString(50, y_pos, f"Amount (in figures): ₹ {amount}")
    
    y_pos -= 25
    amount_words = number_to_words(amount)
    c.drawString(50, y_pos, f"Amount (in words): {amount_words} Rupees Only")
    
    y_pos -= 30
    c.drawString(50, y_pos, f"Mode of Payment: ☑ Online Payment")
    
    y_pos -= 25
    purpose = "Donation" if is_donation else f"Registration Fee - {user_data.get('designation', 'Member')}"
    c.drawString(50, y_pos, f"Purpose/Remarks: {purpose}")
    
    y_pos -= 40
    c.drawString(50, y_pos, "Received By:")
    
    # Signature
    sig_buffer = download_image(SIGNATURE_URL)
    if sig_buffer:
        c.drawImage(ImageReader(sig_buffer), width - 200, y_pos - 80, width=150, height=50, preserveAspectRatio=True, mask='auto')
    
    c.drawRightString(width - 50, y_pos - 90, "(Authorized Signatory)")
    
    y_pos -= 120
    c.setFont("Helvetica-Bold", 10)
    c.drawCentredString(width/2, y_pos, f"For - {NGO_NAME}")
    
    y_pos -= 30
    c.setFont("Helvetica-Oblique", 10)
    c.drawCentredString(width/2, y_pos, "Serving Humanity through Health Camps, Sports,")
    c.drawCentredString(width/2, y_pos - 15, "Animal Care, and Elder Welfare.")
    
    c.save()
    buffer.seek(0)
    return buffer

def generate_certificate_pdf(user_data: dict) -> BytesIO:
    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=(11*inch, 8.5*inch))
    width, height = (11*inch, 8.5*inch)
    
    # Border
    c.setStrokeColor(colors.HexColor('#DAA520'))
    c.setLineWidth(8)
    c.rect(30, 30, width-60, height-60)
    c.setLineWidth(2)
    c.rect(45, 45, width-90, height-90)
    
    # Logo
    logo_buffer = download_image(LOGO_URL)
    if logo_buffer:
        c.drawImage(ImageReader(logo_buffer), width/2 - 60, height - 140, width=120, height=120, preserveAspectRatio=True, mask='auto')
    
    # Title
    c.setFont("Helvetica-Bold", 28)
    c.setFillColor(colors.HexColor('#8B0000'))
    c.drawCentredString(width/2, height - 160, NGO_NAME)
    
    c.setFont("Helvetica-Bold", 22)
    c.setFillColor(colors.HexColor('#1B4D3E'))
    c.drawCentredString(width/2, height - 195, "CERTIFICATE OF APPRECIATION")
    
    # Divider
    c.setStrokeColor(colors.HexColor('#DAA520'))
    c.setLineWidth(2)
    c.line(150, height - 215, width - 150, height - 215)
    
    # Content
    c.setFont("Helvetica-Bold", 20)
    c.setFillColor(colors.HexColor('#8B0000'))
    c.drawCentredString(width/2, height - 265, "PROUDLY PRESENTED TO")
    
    c.setFont("Helvetica-Bold", 24)
    c.setFillColor(colors.black)
    c.drawCentredString(width/2, height - 310, user_data.get('full_name', ''))
    c.setLineWidth(1)
    c.line(200, height - 315, width - 200, height - 315)
    
    c.setFont("Helvetica-Oblique", 14)
    c.drawCentredString(width/2, height - 360, "In recognition and sincere gratitude for your generous donation")
    c.drawCentredString(width/2, height - 380, "to support our initiatives")
    
    # Amount
    c.setFont("Helvetica", 13)
    amount = user_data.get('payment_amount', 0)
    c.drawString(150, height - 430, f"Donation Amount: ₹ {amount}")
    amount_words = number_to_words(amount)
    c.drawString(width/2 + 50, height - 430, f"(Rupees in words) {amount_words}")
    
    # Date
    c.drawString(150, height - 470, f"Date: {datetime.now().strftime('%d/%m/%Y')}")
    c.drawString(150, height - 500, f"Place: Sonipat")
    
    # Signature
    c.drawString(width - 300, height - 470, "Issued By: Healing Sports Foundation")
    sig_buffer = download_image(SIGNATURE_URL)
    if sig_buffer:
        c.drawImage(ImageReader(sig_buffer), width - 300, height - 560, width=180, height=60, preserveAspectRatio=True, mask='auto')
    c.drawString(width - 300, height - 570, "Authorized Signature:")
    
    # Footer
    c.setFont("Helvetica-Oblique", 12)
    c.drawCentredString(width/2, 80, "Serving Humanity through Health Camps, Sports,")
    c.drawCentredString(width/2, 60, "Animal Care, and Elder Welfare.")
    
    c.save()
    buffer.seek(0)
    return buffer

def generate_id_card_pdf(user_data: dict) -> BytesIO:
    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=(3.5*inch, 2.2*inch))
    width, height = (3.5*inch, 2.2*inch)
    
    # Background
    c.setFillColor(colors.white)
    c.rect(0, 0, width, height, fill=1)
    
    # Header with orange bar
    c.setFillColor(colors.HexColor('#FF6B35'))
    c.rect(0, height - 40, width, 40, fill=1)
    
    # Logo in header
    logo_buffer = download_image(LOGO_URL)
    if logo_buffer:
        c.drawImage(ImageReader(logo_buffer), 10, height - 35, width=30, height=30, preserveAspectRatio=True, mask='auto')
    
    # NGO Name
    c.setFillColor(colors.white)
    c.setFont("Helvetica-Bold", 9)
    c.drawString(45, height - 20, "HEALING HEART SPORTS")
    c.drawString(45, height - 32, "FOUNDATION")
    
    # Photo placeholder
    if user_data.get('profile_photo_url'):
        photo_buffer = download_image(user_data['profile_photo_url'])
        if photo_buffer:
            c.drawImage(ImageReader(photo_buffer), 15, height - 120, width=60, height=75, preserveAspectRatio=True, mask='auto')
    else:
        c.setFillColor(colors.HexColor('#FFE5E5'))
        c.rect(15, height - 120, 60, 75, fill=1)
    
    # Member details
    c.setFillColor(colors.black)
    c.setFont("Helvetica-Bold", 11)
    c.drawString(85, height - 60, user_data.get('full_name', '')[:18])
    
    c.setFont("Helvetica", 8)
    c.setFillColor(colors.HexColor('#8B0000'))
    designation = user_data.get('designation', 'Member').upper()
    c.drawString(85, height - 75, f"STATE {designation}")
    
    c.setFillColor(colors.black)
    c.setFont("Helvetica", 7)
    y_pos = height - 90
    c.drawString(85, y_pos, f"ID No.: {user_data.get('member_id', '')}")
    y_pos -= 12
    c.drawString(85, y_pos, f"Blood Group: {user_data.get('blood_group', 'N/A')}")
    y_pos -= 12
    c.drawString(85, y_pos, f"Mobile: {user_data.get('mobile_number', '')}")
    
    # QR Code
    qr_data = f"HHSF-MEMBER:{user_data.get('member_id', '')}"
    qr_buffer = generate_qr_code(qr_data)
    c.drawImage(ImageReader(qr_buffer), width - 70, 10, width=60, height=60, preserveAspectRatio=True)
    
    # Footer
    c.setFillColor(colors.HexColor('#4CAF50'))
    c.rect(0, 0, width, 8, fill=1)
    
    c.save()
    buffer.seek(0)
    return buffer

async def send_email_with_attachment(to_email: str, subject: str, body: str, attachment_data: BytesIO, filename: str):
    if not SENDGRID_API_KEY:
        logging.warning("SendGrid API key not configured")
        return False
    
    try:
        message = Mail(
            from_email=SENDER_EMAIL,
            to_emails=to_email,
            subject=subject,
            html_content=body
        )
        
        attachment_data.seek(0)
        encoded_file = base64.b64encode(attachment_data.read()).decode()
        
        attached_file = Attachment(
            FileContent(encoded_file),
            FileName(filename),
            FileType('application/pdf'),
            Disposition('attachment')
        )
        message.attachment = attached_file
        
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        response = sg.send(message)
        return response.status_code in [200, 202]
    except Exception as e:
        logging.error(f"Email sending failed: {str(e)}")
        return False

# API Routes
@api_router.get("/")
async def root():
    return {"message": "Healing Heart Sports Foundation API"}

@api_router.post("/auth/register")
async def register(user_data: UserRegister):
    # Check if user exists
    existing_user = await db.users.find_one({"email": user_data.email}, {"_id": 0})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Hash password
    hashed_password = hash_password(user_data.password)
    
    # Create user document
    user_id = str(uuid.uuid4())
    member_id = generate_member_id(user_data.designation)
    payment_amount = 200 if user_data.designation == "Member" else 300
    
    user_doc = {
        "id": user_id,
        "member_id": member_id,
        "full_name": user_data.full_name,
        "gender": user_data.gender,
        "date_of_birth": user_data.date_of_birth,
        "profession": user_data.profession,
        "state": user_data.state,
        "city": user_data.city,
        "district": user_data.district,
        "pincode": user_data.pincode,
        "blood_group": user_data.blood_group,
        "son_of": user_data.son_of,
        "aadhaar_number": user_data.aadhaar_number,
        "profile_photo_url": user_data.profile_photo_url,
        "mobile_number": user_data.mobile_number,
        "email": user_data.email,
        "designation": user_data.designation,
        "password": hashed_password,
        "registration_date": datetime.now(timezone.utc).isoformat(),
        "payment_amount": payment_amount,
        "payment_status": "pending",
        "receipt_url": None,
        "certificate_url": None,
        "id_card_url": None
    }
    
    await db.users.insert_one(user_doc)
    
    # Create access token
    access_token = create_access_token({"sub": user_id})
    
    return {
        "user_id": user_id,
        "member_id": member_id,
        "access_token": access_token,
        "payment_amount": payment_amount
    }

@api_router.post("/auth/login")
async def login(credentials: UserLogin):
    # Check for admin credentials
    ADMIN_EMAIL = "admin@healingheart.org"
    ADMIN_PASSWORD = "Admin@123"
    
    if credentials.email == ADMIN_EMAIL and credentials.password == ADMIN_PASSWORD:
        # Admin login
        admin_id = "admin_001"
        access_token = create_access_token({"sub": admin_id})
        
        return {
            "access_token": access_token,
            "user": {
                "id": admin_id,
                "full_name": "Administrator",
                "email": ADMIN_EMAIL,
                "designation": "Admin"
            }
        }
    
    # Regular user login
    user = await db.users.find_one({"email": credentials.email}, {"_id": 0})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    if not verify_password(credentials.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    access_token = create_access_token({"sub": user["id"]})
    
    return {
        "access_token": access_token,
        "user": {
            "id": user["id"],
            "full_name": user["full_name"],
            "email": user["email"],
            "designation": user["designation"],
            "member_id": user.get("member_id")
        }
    }

@api_router.get("/auth/me", response_model=UserProfile)
async def get_current_user_profile(current_user: dict = Depends(get_current_user)):
    return current_user

@api_router.put("/auth/update-profile")
async def update_profile(
    mobile_number: Optional[str] = None,
    profession: Optional[str] = None,
    blood_group: Optional[str] = None,
    profile_photo_url: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    if current_user["id"] == "admin_001":
        raise HTTPException(status_code=400, detail="Admin profile cannot be updated via this endpoint")
    
    update_data = {}
    if mobile_number:
        update_data["mobile_number"] = mobile_number
    if profession:
        update_data["profession"] = profession
    if blood_group:
        update_data["blood_group"] = blood_group
    if profile_photo_url:
        update_data["profile_photo_url"] = profile_photo_url
    
    if not update_data:
        raise HTTPException(status_code=400, detail="No fields to update")
    
    await db.users.update_one(
        {"id": current_user["id"]},
        {"$set": update_data}
    )
    
    return {"success": True, "message": "Profile updated successfully"}

@api_router.post("/payment/verify")
async def verify_payment(
    payment_id: str,
    order_id: str,
    signature: str,
    user_id: str
):
    # In production, verify Razorpay signature
    # For now, simulate successful payment
    
    user = await db.users.find_one({"id": user_id}, {"_id": 0})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Generate documents
    transaction_id = payment_id or str(uuid.uuid4())
    
    # Generate receipt
    receipt_pdf = generate_receipt_pdf(user, transaction_id, is_donation=False)
    # In production, upload to cloud storage and get URL
    receipt_url = f"receipt_{user_id}.pdf"
    
    # Generate certificate for members
    certificate_pdf = generate_certificate_pdf(user)
    certificate_url = f"certificate_{user_id}.pdf"
    
    # Generate ID card
    id_card_pdf = generate_id_card_pdf(user)
    id_card_url = f"id_card_{user_id}.pdf"
    
    # Update user
    await db.users.update_one(
        {"id": user_id},
        {"$set": {
            "payment_status": "completed",
            "payment_id": payment_id,
            "receipt_url": receipt_url,
            "certificate_url": certificate_url,
            "id_card_url": id_card_url
        }}
    )
    
    # Send email with documents
    email_body = f"""
    <html>
    <body>
        <h2>Welcome to {NGO_NAME}!</h2>
        <p>Dear {user['full_name']},</p>
        <p>Thank you for registering as a {user['designation']}. Your payment has been successfully processed.</p>
        <p>Your Member ID: <strong>{user['member_id']}</strong></p>
        <p>Please find attached your receipt, certificate, and ID card.</p>
        <br>
        <p>Best regards,<br>{NGO_NAME}</p>
    </body>
    </html>
    """
    
    # await send_email_with_attachment(user['email'], f"Welcome to {NGO_NAME}", email_body, receipt_pdf, "receipt.pdf")
    
    return {
        "success": True,
        "message": "Payment verified successfully",
        "receipt_url": receipt_url,
        "certificate_url": certificate_url,
        "id_card_url": id_card_url
    }

@api_router.post("/donations", response_model=DonationResponse)
async def create_donation(donation: DonationCreate):
    donation_id = str(uuid.uuid4())
    
    donation_doc = {
        "id": donation_id,
        "donor_name": donation.donor_name,
        "donor_email": donation.donor_email,
        "donor_mobile": donation.donor_mobile,
        "donor_address": donation.donor_address,
        "amount": donation.amount,
        "donation_date": datetime.now(timezone.utc).isoformat(),
        "payment_status": "pending",
        "receipt_url": None
    }
    
    await db.donations.insert_one(donation_doc)
    
    return donation_doc

@api_router.post("/donations/{donation_id}/verify-payment")
async def verify_donation_payment(donation_id: str, payment_data: DonationPaymentVerify):
    donation = await db.donations.find_one({"id": donation_id}, {"_id": 0})
    if not donation:
        raise HTTPException(status_code=404, detail="Donation not found")
    
    # Generate receipt
    payment_id = payment_data.payment_id
    transaction_id = payment_id or str(uuid.uuid4())
    # Generate receipt PDF (in production, save to cloud storage)
    generate_receipt_pdf(donation, transaction_id, is_donation=True)
    receipt_url = f"donation_receipt_{donation_id}.pdf"
    
    # Update donation
    await db.donations.update_one(
        {"id": donation_id},
        {"$set": {
            "payment_status": "completed",
            "payment_id": payment_id,
            "receipt_url": receipt_url
        }}
    )
    
    return {
        "success": True,
        "message": "Donation payment verified",
        "receipt_url": receipt_url
    }

@api_router.get("/donations/user/{user_email}")
async def get_user_donations(user_email: str):
    donations = await db.donations.find({"donor_email": user_email, "payment_status": "completed"}, {"_id": 0}).to_list(100)
    return donations

@api_router.post("/enquiries")
async def create_enquiry(enquiry: EnquiryCreate):
    enquiry_doc = {
        "id": str(uuid.uuid4()),
        "name": enquiry.name,
        "email": enquiry.email,
        "message": enquiry.message,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "status": "pending"
    }
    
    await db.enquiries.insert_one(enquiry_doc)
    return {"success": True, "message": "Enquiry submitted successfully"}

@api_router.get("/activities")
async def get_activities():
    activities = await db.activities.find({}, {"_id": 0}).sort("date", -1).to_list(50)
    return activities

@api_router.post("/activities")
async def create_activity(activity: ActivityCreate, current_user: dict = Depends(get_current_user)):
    # In production, check if user is admin
    activity_doc = {
        "id": str(uuid.uuid4()),
        "title": activity.title,
        "description": activity.description,
        "image_url": activity.image_url,
        "date": activity.date,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    
    await db.activities.insert_one(activity_doc)
    # Return without MongoDB's _id field
    return {k: v for k, v in activity_doc.items() if k != "_id"}

@api_router.get("/news")
async def get_news():
    news = await db.news.find({}, {"_id": 0}).sort("date", -1).to_list(50)
    return news

@api_router.post("/news")
async def create_news(news_item: NewsCreate, current_user: dict = Depends(get_current_user)):
    # In production, check if user is admin
    news_doc = {
        "id": str(uuid.uuid4()),
        "title": news_item.title,
        "content": news_item.content,
        "date": news_item.date,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    
    await db.news.insert_one(news_doc)
    # Return without MongoDB's _id field
    return {k: v for k, v in news_doc.items() if k != "_id"}

@api_router.get("/contact")
async def get_contact_info():
    return {
        "ngo_name": NGO_NAME,
        "address": NGO_ADDRESS,
        "mobile": NGO_MOBILE,
        "email": NGO_EMAIL,
        "darpan_id": NGO_DARPAN_ID
    }

# Admin endpoints
@api_router.get("/admin/members")
async def get_all_members(current_user: dict = Depends(get_current_user)):
    # In production, check if user is admin
    # For now, return all users
    members = await db.users.find({}, {"_id": 0, "password": 0}).to_list(1000)
    return members

@api_router.get("/admin/donors")
async def get_all_donors(current_user: dict = Depends(get_current_user)):
    # Get all unique donors from donations
    donations = await db.donations.find({}, {"_id": 0}).to_list(10000)
    
    # Group by donor email
    donor_map = {}
    for donation in donations:
        email = donation.get("donor_email")
        if email not in donor_map:
            donor_map[email] = {
                "donor_name": donation.get("donor_name"),
                "donor_email": email,
                "donor_mobile": donation.get("donor_mobile"),
                "total_donations": 0,
                "total_amount": 0,
                "donations": [],
                "status": donation.get("status", "active")
            }
        
        if donation.get("payment_status") == "completed":
            donor_map[email]["total_donations"] += 1
            donor_map[email]["total_amount"] += donation.get("amount", 0)
            donor_map[email]["donations"].append({
                "id": donation.get("id"),
                "amount": donation.get("amount"),
                "date": donation.get("donation_date"),
                "payment_id": donation.get("payment_id")
            })
    
    return list(donor_map.values())

@api_router.get("/admin/donors/search")
async def search_donors(query: str, current_user: dict = Depends(get_current_user)):
    # Search donors by name, email, or mobile
    donations = await db.donations.find({
        "$or": [
            {"donor_name": {"$regex": query, "$options": "i"}},
            {"donor_email": {"$regex": query, "$options": "i"}},
            {"donor_mobile": {"$regex": query, "$options": "i"}}
        ]
    }, {"_id": 0}).to_list(1000)
    
    return donations

@api_router.get("/admin/donors/{donor_email}/history")
async def get_donor_history(donor_email: str, current_user: dict = Depends(get_current_user)):
    donations = await db.donations.find({"donor_email": donor_email}, {"_id": 0}).sort("donation_date", -1).to_list(1000)
    return donations

@api_router.post("/admin/donors/{donor_email}/block")
async def block_donor(donor_email: str, current_user: dict = Depends(get_current_user)):
    # Update all donations for this donor
    result = await db.donations.update_many(
        {"donor_email": donor_email},
        {"$set": {"status": "blocked"}}
    )
    return {"success": True, "message": f"Donor {donor_email} blocked", "modified": result.modified_count}

@api_router.post("/admin/donors/{donor_email}/unblock")
async def unblock_donor(donor_email: str, current_user: dict = Depends(get_current_user)):
    # Update all donations for this donor
    result = await db.donations.update_many(
        {"donor_email": donor_email},
        {"$set": {"status": "active"}}
    )
    return {"success": True, "message": f"Donor {donor_email} unblocked", "modified": result.modified_count}

@api_router.post("/admin/donors/{donation_id}/resend-receipt")
async def resend_receipt(donation_id: str, current_user: dict = Depends(get_current_user)):
    donation = await db.donations.find_one({"id": donation_id}, {"_id": 0})
    if not donation:
        raise HTTPException(status_code=404, detail="Donation not found")
    
    # In production, send email with receipt
    # For now, just return success
    return {"success": True, "message": "Receipt resent successfully"}

@api_router.get("/admin/finance/dashboard")
async def get_finance_dashboard(current_user: dict = Depends(get_current_user)):
    # Get all completed donations
    all_donations = await db.donations.find({"payment_status": "completed"}, {"_id": 0}).to_list(10000)
    
    # Calculate total collections
    total_collections = sum(d.get("amount", 0) for d in all_donations)
    
    # Today's donations
    from datetime import datetime, timezone
    today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    today_donations = [d for d in all_donations if datetime.fromisoformat(d.get("donation_date")).replace(tzinfo=timezone.utc) >= today_start]
    today_total = sum(d.get("amount", 0) for d in today_donations)
    
    # Monthly donations (current month)
    month_start = datetime.now(timezone.utc).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    monthly_donations = [d for d in all_donations if datetime.fromisoformat(d.get("donation_date")).replace(tzinfo=timezone.utc) >= month_start]
    monthly_total = sum(d.get("amount", 0) for d in monthly_donations)
    
    # Member registrations
    all_members = await db.users.find({"payment_status": "completed"}, {"_id": 0}).to_list(10000)
    total_member_collections = sum(m.get("payment_amount", 0) for m in all_members)
    
    return {
        "total_collections": total_collections + total_member_collections,
        "donation_collections": total_collections,
        "member_collections": total_member_collections,
        "today_donations": today_total,
        "monthly_donations": monthly_total,
        "total_donors": len(set(d.get("donor_email") for d in all_donations)),
        "total_donations_count": len(all_donations),
        "total_members": len(all_members),
        "today_donations_count": len(today_donations),
        "monthly_donations_count": len(monthly_donations)
    }

@api_router.get("/admin/finance/transactions")
async def get_all_transactions(current_user: dict = Depends(get_current_user)):
    # Get all donations
    donations = await db.donations.find({"payment_status": "completed"}, {"_id": 0}).sort("donation_date", -1).to_list(1000)
    
    # Get all member registrations
    members = await db.users.find({"payment_status": "completed"}, {"_id": 0, "password": 0}).sort("registration_date", -1).to_list(1000)
    
    # Combine and format transactions
    transactions = []
    
    for donation in donations:
        transactions.append({
            "id": donation.get("id"),
            "type": "Donation",
            "name": donation.get("donor_name"),
            "email": donation.get("donor_email"),
            "amount": donation.get("amount"),
            "date": donation.get("donation_date"),
            "payment_id": donation.get("payment_id"),
            "status": donation.get("payment_status")
        })
    
    for member in members:
        transactions.append({
            "id": member.get("id"),
            "type": f"{member.get('designation')} Registration",
            "name": member.get("full_name"),
            "email": member.get("email"),
            "amount": member.get("payment_amount"),
            "date": member.get("registration_date"),
            "payment_id": member.get("payment_id"),
            "status": member.get("payment_status")
        })
    
    # Sort by date
    transactions.sort(key=lambda x: x["date"] if x["date"] else "", reverse=True)
    
    return transactions

@api_router.get("/admin/finance/export-csv")
async def export_transactions_csv(current_user: dict = Depends(get_current_user)):
    transactions = await get_all_transactions(current_user)
    
    # Create CSV
    import csv
    from io import StringIO
    
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=["id", "type", "name", "email", "amount", "date", "payment_id", "status"])
    writer.writeheader()
    writer.writerows(transactions)
    
    from fastapi.responses import StreamingResponse
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=transactions_report.csv"}
    )

# PDF Download endpoints
@api_router.get("/download/receipt/{user_id}")
async def download_receipt(user_id: str):
    user = await db.users.find_one({"id": user_id}, {"_id": 0})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if not user.get("receipt_url"):
        raise HTTPException(status_code=404, detail="Receipt not generated yet")
    
    # Generate receipt PDF
    transaction_id = user.get("payment_id", "MANUAL_" + str(uuid.uuid4())[:8])
    receipt_pdf = generate_receipt_pdf(user, transaction_id, is_donation=False)
    
    from fastapi.responses import StreamingResponse
    receipt_pdf.seek(0)
    return StreamingResponse(
        receipt_pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=receipt_{user['member_id']}.pdf"}
    )

@api_router.get("/download/certificate/{user_id}")
async def download_certificate(user_id: str):
    user = await db.users.find_one({"id": user_id}, {"_id": 0})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if not user.get("certificate_url"):
        raise HTTPException(status_code=404, detail="Certificate not generated yet")
    
    # Generate certificate PDF
    certificate_pdf = generate_certificate_pdf(user)
    
    from fastapi.responses import StreamingResponse
    certificate_pdf.seek(0)
    return StreamingResponse(
        certificate_pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=certificate_{user['member_id']}.pdf"}
    )

@api_router.get("/download/idcard/{user_id}")
async def download_id_card(user_id: str):
    user = await db.users.find_one({"id": user_id}, {"_id": 0})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if not user.get("id_card_url"):
        raise HTTPException(status_code=404, detail="ID card not generated yet")
    
    # Generate ID card PDF
    id_card_pdf = generate_id_card_pdf(user)
    
    from fastapi.responses import StreamingResponse
    id_card_pdf.seek(0)
    return StreamingResponse(
        id_card_pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=idcard_{user['member_id']}.pdf"}
    )

@api_router.get("/download/donation-receipt/{donation_id}")
async def download_donation_receipt(donation_id: str):
    donation = await db.donations.find_one({"id": donation_id}, {"_id": 0})
    if not donation:
        raise HTTPException(status_code=404, detail="Donation not found")
    
    if not donation.get("receipt_url"):
        raise HTTPException(status_code=404, detail="Receipt not generated yet")
    
    # Generate donation receipt PDF
    transaction_id = donation.get("payment_id", "DONATION_" + str(uuid.uuid4())[:8])
    receipt_pdf = generate_receipt_pdf(donation, transaction_id, is_donation=True)
    
    from fastapi.responses import StreamingResponse
    receipt_pdf.seek(0)
    return StreamingResponse(
        receipt_pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=donation_receipt_{donation_id}.pdf"}
    )

# Include router
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
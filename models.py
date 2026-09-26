from datetime import date
from typing import Literal

from pydantic import BaseModel, Field


class CustomerCreate(BaseModel):
    customer_id: str = Field(min_length=1, max_length=40)
    name: str = Field(min_length=1, max_length=120)
    date_of_birth: str = Field(default="", max_length=40, description="Source DOB text; supported formats are DD/MM/YYYY, DD-MM-YYYY, YYYY-MM-DD")
    branch_id: str = Field(min_length=1, max_length=40)
    branch_name: str = Field(min_length=1, max_length=100)
    account_number: str = Field(min_length=1, max_length=40)
    customer_type: Literal["INDIVIDUAL", "JOINT"] = "INDIVIDUAL"
    document_type: str = Field(min_length=1, max_length=60)
    document_number: str = Field(default="", max_length=80)
    issue_date: str = Field(default="", max_length=40)
    expiry_date: str = Field(default="", max_length=40)
    kyc_date: str = Field(default="", max_length=40)


class RekycScheduleRequest(BaseModel):
    scheduled_date: date
    assigned_officer: str = Field(default="", max_length=120)
    remarks: str = Field(default="", max_length=1000)


class RekycCompleteRequest(BaseModel):
    completed_date: date = Field(default_factory=date.today)
    new_expiry_date: date
    remarks: str = Field(default="", max_length=1000)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class CustomerPage(BaseModel):
    items: list[dict]
    page: int
    page_size: int
    total: int

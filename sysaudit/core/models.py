#create a data model to represent the result of a check 
from dataclasses import dataclass


@dataclass
class CheckResult:
    name: str
    status: str
    message: str

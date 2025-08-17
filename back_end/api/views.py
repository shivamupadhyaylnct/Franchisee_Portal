import pyodbc
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import generics
from .serializers import UserSerializer
from rest_framework.permissions import IsAuthenticated, AllowAny
import os
from dotenv import load_dotenv
import simplejson as json
from decimal import Decimal
# from pyrfc import Connection
import base64
from io import BytesIO
from num2words import num2words
from fpdf import FPDF
from django.conf import settings
from dateutil import parser
from datetime import datetime, timedelta
from django.contrib.auth.hashers import make_password
from django.contrib.auth.hashers import check_password
from django.core.cache import cache
from django.core.mail import send_mail
import random

load_dotenv()

def get_db_connection():
    conn = pyodbc.connect(
        f"DRIVER={os.getenv('DB_DRIVER')};"
        f"SERVER={os.getenv('DB_SERVER')};"
        f"DATABASE={os.getenv('DB_NAME')};"
        f"UID={os.getenv('DB_USER')};"
        f"PWD={os.getenv('DB_PASSWORD')}"
    )
    return conn

class TempUser:
    def __init__(self, user_id):
        self.id = user_id

class CreateUserView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [AllowAny] 

#================================ ( Login Logics ) ==============================================

@api_view(["POST"])
@permission_classes([AllowAny])
def user_login(request):
    username = request.data.get("username")
    password = request.data.get("password")

    print("inside api")

    if not username or not password:
        return Response({"code": 400, "status": "Failure", "message": "Username and password are required"}, status=400)

    conn = None
    try:
        # Connect to MSSQL
        conn = get_db_connection()
        cursor = conn.cursor()

        # Fetch user data from MSSQL
        cursor.execute("SELECT vendorCode, password, usertype, email, panno FROM tbl_mVendor WHERE vendorCode = ?", username)
        user = cursor.fetchone()

        print("User is-:",user)

        if not user:
            return Response({"code": 404, "status": "Failure", "message": "User not found"}, status=200)

        # Compare stored and input passwords (Plain Text)
        stored_password = user[1]  # Password from DB
        print("stored_password",stored_password)
        if not check_password(password, stored_password):
            return Response({"code": 401, "status": "Failure", "message": "Incorrect Password"}, status=200)
        # Create a fake user object for JWT
        user_obj = TempUser(user[0])  # User ID from MSSQL
        refresh = RefreshToken.for_user(user_obj)  # Generate JWT Token
        class UserData():
            def __init__(self, UserName, UserType, EmailId, PANNO):
                self.UserName = UserName
                self.UserType = UserType
                self.EmailId = EmailId
                self.PANNO = PANNO
            def to_dict(self):
                return {
                    "UserName": self.UserName,
                    "UserType": self.UserType,
                    "EmailId": self.EmailId,
                    "PANNO": self.PANNO
                }
        cuser = UserData(user[0], user[2], user[3],user[4])
        user_data = []
        user_data.append(cuser.to_dict())
        return Response({
            "code": 201,
            "status": "Success",
            "message": "User logged in successfully",
            "access_token": str(refresh.access_token),
            "refresh_token": str(refresh),
            "user_details": user_data
        }, status=200)

    except Exception as e:
        return Response({"code": 500, "status": "Error", "message": "Error logging in", "error": str(e)}, status=500)

    finally:
        if conn:
            conn.close() 

@api_view(["GET"])
@permission_classes([AllowAny])
def test(request):
    data = {"message": "This is a GET request test response"}
    return Response(data)

# @api_view(["POST"])
# @permission_classes([AllowAny])
# def user_login(request):
#     username = request.data.get("username")
#     password = request.data.get("password")

#     if not username or not password:
#         return Response({"code": 400, "status": "Failure", "message": "Username and password are required"}, status=400)

#     conn = None
#     try:
#         # Connect to MSSQL
#         conn = get_db_connection()
#         cursor = conn.cursor()

#         # Fetch user data from MSSQL
#         cursor.execute("SELECT vendorCode, password, usertype, email, panno FROM tbl_mVendor WHERE vendorCode = ?", username)  
#         user = cursor.fetchone() 
#         print("user is",user)
#         if not user:
#             return Response({"code": 404, "status": "Failure", "message": "User not found"}, status=200)

#         # Compare stored and input passwords (Plain Text)
#         stored_password = user[1]  # Password from DB
#         if stored_password.strip() != password.strip():
#             return Response({"code": 401, "status": "Failure", "message": "Incorrect Password"}, status=200)

#         # Create a fake user object for JWT
#         user_obj = TempUser(user[0])  # User ID from MSSQL
#         refresh = RefreshToken.for_user(user_obj)  # Generate JWT Token

#         return Response({
#             "code": 201,
#             "status": "Success",
#             "message": "User logged in successfully",
#             "access_token": str(refresh.access_token),
#             "refresh_token": str(refresh),
#             "user_details": {
#         "UserName": user[0],
#         "UserType": user[2],
#         "EmailId": user[3],
#         "PANNO": user[4]
#     }
#         }, status=200)

#     except Exception as e:
#         return Response({"code": 500, "status": "Error", "message": "Error logging in", "error": str(e)}, status=500)

#     finally:
#         if conn:
#             conn.close() 


@api_view(["POST"])
@permission_classes([AllowAny])
def user_login_otp(request):
    mobileNumber = request.data.get("mobileNumber")
    print("mobileNumber",mobileNumber)
    if not mobileNumber:
        return Response({
            "code": 400,
            "status": "Failure",
            "message": "mobileNumber is required"
        }, status=400)

    try:
        conn = get_db_connection() 
        with conn.cursor() as cursor:

 # Step 1: Get franchiseeUID from (tbl_mFranchisee)
            cursor.execute(""" SELECT franchiseeUID FROM tbl_mFranchisee WHERE mobileNumber = ? """, 
            (mobileNumber,))
            franchisee_mobile = cursor.fetchone()

            if not franchisee_mobile :
                return Response({
                    "code": 404,
                    "status": "Failure",
                    "message": "Mobile number not registered"
                }, status=404)
            franchiseeUID = franchisee_mobile[0]
            print("Franchisee UID is =>",franchiseeUID)

 # Step 2: Get vendorUIDs from (tbl_xFranchiseeVendor)
            cursor.execute(""" SELECT vendorUID FROM tbl_xFranchiseeVendor WHERE franchiseeUID = ? """, (franchiseeUID,))
            vendor_rows = cursor.fetchall()
            vendorUID = tuple(row[0] for row in vendor_rows) # for ensuring flat tuple
            print("Total number of the vender",len(vendorUID))

            if not vendorUID: 
                return Response({ 
                    "code": 404, 
                    "status": "Failure", 
                    "message": "No vendors associated with this franchisee" 
                    },status=404)

 # Step 3: Get vendor details from (tbl_mVendor)
            placeholders = ','.join(['?'] * len(vendorUID)) # based on vender --list is ['?', '?', '?'] 
            query = f"""
                SELECT vendorCode AS UserName,
                       usertype AS UserType, 
                       email AS EmailId,
                       panno AS PANNO 
                FROM tbl_mVendor 
                WHERE vendorUID IN ({placeholders}) """ #// placeholders = (?, ?, ?)
            cursor.execute(query, vendorUID) # fill all the numbers in the venderUID present

            columns = [col[0] for col in cursor.description] # return column name
            users = [dict(zip(columns, row)) for row in cursor.fetchall()] #  LOOP dictionary object converted
            return Response({
                "code": 200,
                "status": "Success",
                "message": "User(s) found",
                "data": users
            }, status=200)


    except Exception as e:
        return Response({
            "code": 500,
            "status": "Error",
            "message": "Error while fetching user details",
            "error": str(e)
        }, status=500)

#===============================================================================================

#Bapii
@api_view(["POST"])
@permission_classes([AllowAny])
def store_detail(request):
    storeUID = request.data.get("storeUID")
    
    if not storeUID:
        return Response({"code": 400, "status": "Failure", "message": "StoreUID is required"}, status=400)

    try:
        # conn = Connection(ashost='172.22.224.9', sysnr='06', client='300', user='RFCUSER_ASP', passwd='Meridian@12345', lang='EN')
	    # print("Connection to SAP successful")
        # result = conn.call('ZBAPIFRANCHISE', LIFNR_VN=u'1301443')
        return Response({
            "code": 201,
            "status": "Success",
            "store_details": {
                   "RETURN": {
            "TYPE": "",
            "ID": "",
            "NUMBER": "000",
            "MESSAGE": "",
            "LOG_NO": "",
            "LOG_MSG_NO": "000000",
            "MESSAGE_V1": "",
            "MESSAGE_V2": "",
            "MESSAGE_V3": "",
            "MESSAGE_V4": "",
            "PARAMETER": "",
            "ROW": 0,
            "FIELD": "",
            "SYSTEM": ""
        },
        "STORE": {
            "NAME": "ISHA DISTRIBUTION HOUSE PVT LTD",
            "J_1IPANNO": "AAACI9935R",
            "HOUSE_NUM1": "",
            "STREET": "No.6, Entry from Middleton Street",
            "CITY1": "Kolkatta",
            "POST_CODE1": "700071",
            "LANDX": "India",
            "TEL_NUMBER": "",
            "SMTP_ADDR": "manojidh@gmail.com",
            "SERVICETAX": "",
            "BANKN": "02864010000470",
            "BANKA": "Oriental Bank of Commerce",
            "REGIO": "19",
            "BEZEI": "West Bengal",
            "IFSC": "ORBC0100286",
            "STCD3": "",
            "STR_OPN_DATE": "20250709"
        }
    }
        }, status=200)
        
        
    except Exception as e:
        return Response({"code": 500, "status": "Error", "message": "Error connecting to SAP:", "error": str(e)}, status=500)

    # finally:
    #     if conn:
    #         conn.close() 


#========== ( User Alert API )============ ( Get all Alert Details )===============

# @api_view(["POST"])
# @permission_classes([AllowAny])
# def get_all_alerts(request):
#     conn:None
#     try:
#         alert_names = request.data.get("alertNames", [])
        
#         # if not list or empty, return empty response (don't default)
#         if not isinstance(alert_names, list) or not alert_names:
#             return Response({
#                 "code": 400,
#                 "status": "bad Request",
#                 "message": "No alert names provided, nothing to fetch",
#                 "data": []
#             })

#         conn = get_db_connection()
#         cursor = conn.cursor()
#         today = datetime.now().date()
#         data = []

#         for alert_name in alert_names:
#             cursor.execute("""
#                 SELECT TOP 1 alertName, alertMessage, expiryDate ,isVisible
#                 FROM tbl_Alerts
#                 WHERE alertName = ? AND isVisible = 1
#                 ORDER BY createdAt DESC
#             """, (alert_name,))
#             result = cursor.fetchone()

#             if result:
#                 fetched_alert_name, alert_message, expiry_date, isVisible = result
#                 # expiry_date_obj = parser.parse(expiry_date).date()
#                 expiry_date_obj = expiry_date.date()
#                 remaining_days = (expiry_date_obj - today).days

#                 if fetched_alert_name in ["Stock Block and Payment Hold Alerts"]:
#                   is_expire = 1  # Force expire flag to 1
#                 else:
#                   is_expire = 1 if remaining_days > 0 else 0

#                 alert_data = {
#                     "alertName": fetched_alert_name,
#                     "alertMessage": alert_message,
#                     "remainingDays": remaining_days,
#                     "isExpire": is_expire
#                 }

#                 # ✅ Only include isVisible for Generic Message Alert
#                 if fetched_alert_name == "Generic Message Alert":
#                     alert_data["isVisible"] = bool(isVisible)
#                     alert_data["isExpire"] = 1

#                 data.append(alert_data)


#         return Response({
#             "code": 200,
#             "status": "Success",
#             "message": "Fetched latest alerts",
#             "data": data
#         }, status=200)

#     except Exception as e:
#         return Response({
#             "code": 500,
#             "status": "Error",
#             "message": "Something went wrong",
#             "error": str(e)
#         }, status=500)

#     finally:
#         if conn:
#             conn.close()


@api_view(["POST"])
@permission_classes([AllowAny])
def get_all_alerts(request):
    conn = None
    try:
        alert_names = request.data.get("alertNames", [])
        
        # if not list or empty, return empty response (don't default)
        if not isinstance(alert_names, list) or not alert_names:
            return Response({
                "code": 400,
                "status": "bad Request",
                "message": "No alert names provided, nothing to fetch",
                "data": []
            })

        conn = get_db_connection()
        cursor = conn.cursor()
        today = datetime.now().date()
        data = []

        for alert_name in alert_names:
            if alert_name == "Generic Message Alert":
                query = """
                    SELECT TOP 1 alertName, alertMessage, expiryDate, isVisible
                    FROM tbl_Alerts
                    WHERE alertName = ? 
                    ORDER BY createdAt DESC, alertID DESC
                """
            else:
                query = """
                    SELECT TOP 1 alertName, alertMessage, expiryDate, isVisible
                    FROM tbl_Alerts
                    WHERE alertName = ? AND isVisible = 1
                    ORDER BY createdAt DESC, alertID DESC
                """

            cursor.execute(query, (alert_name,))
            result = cursor.fetchone()

            if result:
                fetched_alert_name, alert_message, expiry_date, isVisible = result
                expiry_date_obj = expiry_date.date()
                remaining_days = (expiry_date_obj - today).days

                if fetched_alert_name in ["Stock Block and Payment Hold Alerts"]:
                    is_expire = 1  # Force expire flag to 1
                else:
                    is_expire = 1 if remaining_days > 0 else 0

                alert_data = {
                    "alertName": fetched_alert_name,
                    "alertMessage": alert_message,
                    "remainingDays": remaining_days,
                    "isExpire": is_expire
                }

                # ✅ Special handling for Generic Message Alert
                if fetched_alert_name == "Generic Message Alert":
                    alert_data["isVisible"] = bool(isVisible)
                    alert_data["isExpire"] = 1  # Always 1

                data.append(alert_data)

        return Response({
            "code": 200,
            "status": "Success",
            "message": "Fetched latest alerts",
            "data": data
        }, status=200)

    except Exception as e:
        return Response({
            "code": 500,
            "status": "Error",
            "message": "Something went wrong",
            "error": str(e)
        }, status=500)

    finally:
        if conn:
            conn.close()


#==========(vendor Codes )=============================

@api_view(['GET'])
@permission_classes([AllowAny])
def get_all_vendors(request):
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            query = """
                SELECT vendorUID, vendorCode 
                FROM tbl_mVendor
            """
            cursor.execute(query)
            rows = cursor.fetchall()

            if not rows:
                return Response({
                    "code": 404,
                    "status": "Error",
                    "message": "No vendors found."
                }, status=404)

            columns = [column[0] for column in cursor.description]
            vendors = [dict(zip(columns, row)) for row in rows]

        return Response({
            "code": 200,
            "status": "Success",
            "vendors": vendors
        }, status=200)

    except Exception as e:
        return Response({
            "code": 500,
            "status": "Error",
            "message": "Internal server error.",
            "error": str(e)
        }, status=500)


#==================(franchisee Name)==============================

@api_view(['GET'])
@permission_classes([AllowAny])
def get_all_franchisees(request):
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            query = """
                SELECT franchiseeUID, franchiseeName 
                FROM tbl_mFranchisee
            """
            cursor.execute(query)
            rows = cursor.fetchall()

            if not rows:
                return Response({
                    "code": 404,
                    "status": "Error",
                    "message": "No franchisees found."
                }, status=404)

            columns = [column[0] for column in cursor.description]
            franchisees = [dict(zip(columns, row)) for row in rows]

        return Response({
            "code": 200,
            "status": "Success",
            "franchisees": franchisees
        }, status=200)

    except Exception as e:
        return Response({
            "code": 500,
            "status": "Error",
            "message": "Internal server error.",
            "error": str(e)
        }, status=500)


#=========( ADMIN API USER )=========( Get All User details )================================= 

@api_view(['GET'])
@permission_classes([AllowAny])
# @permission_classes([IsAuthenticated])  #need of Authentication here
def get_all_user_details(request):
    # Connect to MSSQL
    conn = get_db_connection()
    with conn.cursor() as cursor:
        cursor.execute("""
            SELECT vendorUID, vendorCode, email, address, city, state, pincode, password, panno, usertype
            FROM tbl_mVendor
        """)
        columns = [col[0] for col in cursor.description]
        data = [dict(zip(columns, row)) for row in cursor.fetchall()]
    
    return Response(data)

#=========( ADMIN API USER )=========( Get All User details by Vender Code) ======================= 

@api_view(['GET'])
@permission_classes([AllowAny])
def get_user_detail(request, vendorCode):
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM tbl_mVendor WHERE vendorCode = ?", (vendorCode,))
            row = cursor.fetchone()
            if not row:
                return Response({
                    "code": 404,
                    "status": "Error",
                    "message": "Vendor not found."
                }, status=404)

            columns = [column[0] for column in cursor.description]
            user_data = dict(zip(columns, row))

        return Response(user_data, status=200)

    except Exception as e:
        return Response({
            "code": 500,
            "status": "Error",
            "message": "Internal server error.",
            "error": str(e)
        }, status=500)


#=========( ADMIN API USER )=========( Delete User details )================================= 

@api_view(['DELETE'])
@permission_classes([AllowAny])
def delete_user_detail(request, vendorUID, vendorCode):
    try:
       # Validation
        if not vendorUID or not vendorCode:
            return Response({
                "code": 400,
                "status": "Error",
                "message": "Both 'vendorUID' and 'vendorCode' are required."
            }, status=400)

        # Connect to DB and delete
        conn = get_db_connection()
        with conn.cursor() as cursor:
            delete_query = """ DELETE FROM tbl_mVendor WHERE vendorUID = ? AND vendorCode = ? """
            cursor.execute(delete_query, (vendorUID, vendorCode))
            affected = cursor.rowcount
            conn.commit()

        if affected == 0:
            return Response({
                "code": 404,
                "status": "Error",
                "message": "No matching vendor found."
            }, status=404)

        return Response({
            "code": 200,
            "status": "Success",
            "message": f"Vendor with UID {vendorUID} and Code {vendorCode} deleted successfully."
        }, status=200)

    except Exception as e:
        return Response({
            "code": 500,
            "status": "Error",
            "message": "Internal server error during deletion.",
            "error": str(e)
        }, status=500)

#========== ( ADMIN API USER ) ========(Edit user Details)=================================

@api_view(['PATCH'])
@permission_classes([AllowAny])
def edit_user_detail(request, vendorCode):
    print("vendorcode",vendorCode)
    try:
        update_fields = request.data.copy()
        update_fields.pop('username', None)
        
        # partial update only 
        if not update_fields:
            return Response({
                "code": 400,
                "status": "Error",
                "message": "No data provided for update."
            }, status=400)

        # Build dynamic SET part of SQL for only given fields
        set_clause = ", ".join([f"{key} = ?" for key in update_fields.keys()])
        values = list(update_fields.values())

        # Add WHERE condition value
        values.append(vendorCode)

        # Connect to DB and update
        conn = get_db_connection()
        with conn.cursor() as cursor:
            update_query = f""" UPDATE tbl_mVendor SET {set_clause} WHERE vendorCode = ? """
            cursor.execute(update_query, values)
            affected = cursor.rowcount
            conn.commit()

        if affected == 0:
            return Response({
                "code": 404,
                "status": "Error",
                "message": "No matching vendor found to update."
            }, status=404)

        return Response({
            "code": 200,
            "status": "Success",
            "message": f"Vendor with Code {vendorCode} updated successfully."
        }, status=200)

    except Exception as e:
        return Response({
            "code": 500,
            "status": "Error",
            "message": "Internal server error during update.",
            "error": str(e)
        }, status=500)

#=========== ( ADMIN API USER ) ========(Get user Details)=====================================

@api_view(['POST'])
@permission_classes([AllowAny])
def add_user_details(request):
    try:
        #  Get POST data 
        username = request.data.get("username")
        # password = request.data.get("password")

        hashed_password = make_password(request.data.get("password"))
        state = request.data.get("state")
        city = request.data.get("city")
        pincode = request.data.get("pincode")
        address = request.data.get("address")
        email = request.data.get("email")
        panno = request.data.get("panno")
        userType = request.data.get("userType")

        # validation
        if not all([username, hashed_password, state, city, pincode, address, email, panno, userType]):
            return Response({
                "code": 400,
                "status": "Error",
                "message": "Provide all required form data."
            }, status=400)

        #  Insert into MSSQL DB
        conn = get_db_connection()
        with conn.cursor() as cursor:
            insert_query = """
                INSERT INTO tbl_mVendor 
                (vendorCode, email, address, city, state, pincode, password, panno, usertype)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            cursor.execute(insert_query, (
                username, email, address, city, state, pincode, hashed_password, panno, userType
            ))
            conn.commit()

        # Success response
        return Response({
            "code": 200,
            "status": "Success",
            "message": "User data received successfully",
            "data": {
                "vendorCode": username,  # assuming vendorCode is same as username
                "email": email,
                "address": address,
                "city": city,
                "state": state,
                "pincode": pincode,
                "password": hashed_password,
                "panno": panno,
                "usertype": userType
            }
        }, status=200)

    except Exception as e:
        return Response({
            "code": 500,
            "status": "Error",
            "message": "Database insert failed",
            "error": str(e)
        }, status=500)


#=========== ( ADMIN API Franchise ) ========(Get All Franchisee Details) =====================

@api_view(['GET'])
@permission_classes([AllowAny])  # Use IsAuthenticated if needed
def get_all_franchisee_details(request):
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute(""" SELECT franchiseeUID, franchiseeName, email, mobileNumber, address, city, state, pincode FROM dbo.tbl_mFranchisee """)
            columns = [col[0] for col in cursor.description]
            data = [dict(zip(columns, row)) for row in cursor.fetchall()]
        return Response(data)
    except Exception as e:
        return Response({"error": str(e)}, status=500)

#======( ADMIN API Franchise ) ===== (Get perticular detail of franchise by mobile number ) =======

@api_view(['GET'])
@permission_classes([AllowAny])
def get_franchisee_detail(request, mobileNumber):
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT franchiseeName, email, mobileNumber, address, city, state, pincode FROM tbl_mFranchisee WHERE mobileNumber = ?", (mobileNumber,))
            row = cursor.fetchone()
            
            if not row:
                return Response({
                    "code": 404,
                    "status": "Error",
                    "message": "Franchisee not found."
                }, status=404)

            columns = [column[0] for column in cursor.description]
            user_data = dict(zip(columns, row))

        return Response(user_data, status=200)

    except Exception as e:
        print("Error occurred:", str(e))
        return Response({
            "code": 500,
            "status": "Error",
            "message": "Internal server error.",
            "error": str(e)
        }, status=500)

#=====( ADMIN API Franchise )====== (UPDATE perticular detail of franchise by mobile number ) ============

@api_view(['PATCH'])
@permission_classes([AllowAny])
def update_specific_franchisee(request, mobileNumber):
    try:
        conn = get_db_connection()
        data = request.data
        columns = []
        values = []

        for key, value in data.items():
            columns.append(f"{key} = ?")
            values.append(value)

        if not columns:
            return Response({
                "code": 400,
                "status": "Error",
                "message": "No fields provided for update."
            }, status=400)

        values.append(mobileNumber)
        update_query = f"""
            UPDATE tbl_mFranchisee
            SET {", ".join(columns)}
            WHERE mobileNumber = ?
        """

        with conn.cursor() as cursor:
            cursor.execute(update_query, tuple(values))
            conn.commit()

            if cursor.rowcount == 0:
                return Response({
                    "code": 404,
                    "status": "Error",
                    "message": "Franchisee not found."
                }, status=404)

        return Response({
            "code": 200,
            "status": "Success",
            "message": "Franchisee updated successfully."
        })

    except Exception as e:
        return Response({
            "code": 500,
            "status": "Error",
            "message": "Internal server error.",
            "error": str(e)
        }, status=500)

#=========== ( ADMIN API Franchise ) ========(Add Franchisee Details)=====================================

@api_view(['POST'])
@permission_classes([AllowAny])  # Change to IsAuthenticated if needed
def add_franchisee_details(request):

    try:
        # Step 1: Extract incoming data
        franchiseeName = request.data.get('franchiseeName')
        email = request.data.get('email')
        mobileNumber = request.data.get('mobileNumber')
        address = request.data.get('address')
        city = request.data.get('city')
        state = request.data.get('state')
        pincode = request.data.get('pincode')

        # Step 2: Validation
        if not all([franchiseeName, email, mobileNumber, address, city, state, pincode]):
            return Response({
                "code": 400,
                "status": "Error",
                "message": "Provide all required form data."
            }, status=400)

        # Step 3: Open DB connection and insert data
        conn = get_db_connection()
        with conn.cursor() as cursor:
            insert_query = """
                INSERT INTO dbo.tbl_mFranchisee 
                (franchiseeName, email, mobileNumber, address, city, state, pincode)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """
            cursor.execute(insert_query, (franchiseeName, email, mobileNumber, address, city, state, pincode))
            conn.commit()

       # Success response
        # Step 4: Return success response
        return Response({
            "code": 200,
            "status": "Success",
            "message": "Franchisee data received successfully",
            "data": {
                "franchiseeName": franchiseeName,
                "email": email,
                "mobileNumber": mobileNumber,
                "address": address,
                "city": city,
                "state": state,
                "pincode": pincode
            }
        }, status=200)

    except Exception as e:
        return Response({
            "code": 500,
            "status": "Error",
            "message": "Database insert failed",
            "error": str(e)
        }, status=500)

#========= ( ADMIN API Franchise) ========= ( Delete Franchisee details ) ================================= 

@api_view(['DELETE'])
@permission_classes([AllowAny])
def delete_franchisee_detail(request, mobileNumber):
    try:

        # Validation
        if not mobileNumber:
            return Response({
                "code": 400,
                "status": "Error",
                "message": "Mobile Number is required."
            }, status=400)

        conn = get_db_connection()
        with conn.cursor() as cursor:
            delete_query = "DELETE FROM tbl_mFranchisee WHERE mobileNumber = ?"
            cursor.execute(delete_query, (mobileNumber,))
            affected = cursor.rowcount
            conn.commit()

        if affected == 0:
            return Response({
                "code": 404,
                "status": "Error",
                "message": "No matching mobileNumber found."
            }, status=404)

        return Response({
            "code": 200,
            "status": "Success",
            "message": f"Franchisee with Mobile Number {mobileNumber} deleted successfully."
        }, status=200)

    except Exception as e:
        return Response({
            "code": 500,
            "status": "Error",
            "message": "Internal server error during deletion.",
            "error": str(e)
        }, status=500)

#======== ( ADMIN API Franchisee ) ================ ( vendor Franchisee Mapping )====================

@api_view(['POST'])
@permission_classes([AllowAny])
def franchisee_vendor_mapping(request):
    try:
        franchiseeUID = request.data.get("franchiseeUID")
        vendorUIDs = request.data.get("vendorUID")  # Can be single value or list
        vendorCodes = request.data.get("vendorCode")  # Can be single value or list
        mobileNumber = request.data.get("mobileNumber")

        # Validation
        if not all([franchiseeUID, vendorUIDs, vendorCodes, mobileNumber]):
            return Response({
                "code": 400,
                "status": "Error",
                "message": "All fields (franchiseeUID, vendorUID, vendorCode, mobileNumber) are required."
            }, status=400)

        # Normalize to list if single value
        if not isinstance(vendorUIDs, list):
            vendorUIDs = [vendorUIDs]
        if not isinstance(vendorCodes, list):
            vendorCodes = [vendorCodes]

        if len(vendorUIDs) != len(vendorCodes):
            return Response({
                "code": 400,
                "status": "Error",
                "message": "vendorUID and vendorCode lists must be of the same length."
            }, status=400)

        # DB Insert
        conn = get_db_connection()
        with conn.cursor() as cursor:
            insert_query = """
                INSERT INTO tbl_xFranchiseeVendor 
                (franchiseeUID, vendorUID, mobileNumber, isActive, createdBy, createdDate, vendorCode)
                VALUES (?, ?, ?, ?, ?, GETDATE(), ?)
            """
            for uid, code in zip(vendorUIDs, vendorCodes):
                cursor.execute(insert_query, (
                    int(franchiseeUID),
                    int(uid),
                    int(mobileNumber),
                    1,     # isActive
                    1,     # createdBy
                    code ,
                ))
            conn.commit()

        return Response({
            "code": 200,
            "status": "Success",
            "message": "Franchisee-Vendor mappings inserted successfully.",
            "data": {
                "franchiseeUID": franchiseeUID,
                "vendorUIDs": vendorUIDs,
                "vendorCodes": vendorCodes,
                "mobileNumber": mobileNumber
            }
        }, status=200)

    except Exception as e:
        return Response({
            "code": 500,
            "status": "Error",
            "message": "Database insert failed.",
            "error": str(e)
        }, status=500)

#=========== ( ADMIN API Alert) ============ (Api to Post Alert Message)================================

@api_view(["POST"])
@permission_classes([AllowAny])
def create_alert(request):
    alert_name = request.data.get("alertName")
    alert_message = request.data.get("alertMessage")
    expiry_date = request.data.get("expiryDate") # Optional
    remaining_days = request.data.get("remainingDays") # Optional
    is_visible = 1 if request.data.get("isVisible", True) else 0  # 1 if its true else 0 / Optional field

    if not alert_name or not alert_message:
        return Response({
            "code": 400,
            "status": "Failure",
            "message": "alertName and alertMessage are required"
        }, status=400)

    conn = None
    try:
        today = datetime.now().date()

        if expiry_date:
            print("expiry_date")
            # calculate remaining_days
            expiry_date = parser.parse(expiry_date).date() 
            remaining_days = (expiry_date - today).days # just Provide the number of days like 5
            is_expire = 1 if remaining_days > 0 else 0
            
        elif remaining_days:
            print("remaining_days")
            # If only remaining_days is provided
            try:
                remaining_days = int(remaining_days)
                expiry_date = today + timedelta(days=remaining_days)
                is_expire = 1 if remaining_days > 0 else 0
            except ValueError:
                return Response({
                    "code": 400,
                    "status": "Failure",
                    "message": "remainingDays must be a valid integer"
                }, status=400)

        else:
            print("invoice Submission Reminder")
            # If neither expiry_date nor remaining_days is provided
            expiry_date = today
            remaining_days = 0
            is_expire = 1  # Forced Always 1 
        
        


        conn = get_db_connection()
        cursor = conn.cursor()

        insert_query = """
            INSERT INTO tbl_Alerts (alertName, alertMessage, expiryDate, isVisible, createdAt)
            VALUES (?, ?, ?, ?, ?);
        """
        cursor.execute(insert_query, (
            alert_name,
            alert_message,
            expiry_date.isoformat(),
            is_visible,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Current date & time
        ))
        conn.commit()

        # Get latest alertName by createdAt   only the most recent record
        latest_alert_query = """  
            SELECT TOP 1 alertName
            FROM tbl_Alerts
            ORDER BY createdAt DESC;
        """
        cursor.execute(latest_alert_query)
        latest_alert = cursor.fetchone()[0]

        return Response({
            "code": 201,
            "status": "Success",
            "message": "Alert created",
            "data": {
                "alertName": latest_alert,
                "alertMessage": alert_message,
                "remainingDays": remaining_days,
                "expiryDate": expiry_date.isoformat(),
                "isExpire": is_expire
            }
        }, status=201)

    except Exception as e:
        return Response({
            "code": 500,
            "status": "Error",
            "message": "Something went wrong",
            "error": str(e)
        }, status=500)

    finally:
        if conn:
            conn.close()


#  ==================== ( Admin API Alert) ===================== (API TO FETCH ALL DETAILS) =============================================

@api_view(['GET'])
@permission_classes([AllowAny])
def get_generic_alert(request):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Fetch latest alert based on createdAt + alertID
        cursor.execute("""
            SELECT TOP 1 alertName, alertMessage, isVisible, createdAt
            FROM dbo.tbl_Alerts
            WHERE alertName = ?
            ORDER BY createdAt DESC, alertID DESC
        """, ["Generic Message Alert"])
        
        row = cursor.fetchone()
        cursor.close()
        conn.close()


        if row:
            alert_name, alert_message, is_visible, created_at = row
            print(row)
            data = {
                "alertName": alert_name,
                "alertMessage": alert_message if is_visible == 1 else None,
                "isVisible": bool(is_visible),
                "createdAt": created_at.strftime("%Y-%m-%d %H:%M:%S") if created_at else None
            }
            return Response({
                "code": 200,
                "status": "Success",
                "data": data
            })
        else:
            return Response({
                "code": 404,
                "status": "Not Found",
                "message": "Generic alert not found"
            })

    except Exception as e:
        return Response({
            "code": 500,
            "status": "Error",
            "message": str(e)
        })

# ==============================================================================================

#Bapiii
@api_view(["POST"])
@permission_classes([AllowAny])
def get_franchisee_details(request):
    userName = request.data.get("selectedVendorCode")

    if not userName:
        return Response({
            "code": 400,
            "status": "Failure",
            "message": "selectedVendorCode is required"
        }, status=400)

    try:
        # You can integrate with SAP or database here if needed.
        # For now, returning mock response.

        return Response({
            "code": 200,
            "status": "Success",
            "vendor_details": {
                "RETURN": {
                    "TYPE": "",
                    "ID": "",
                    "NUMBER": "000",
                    "MESSAGE": "",
                    "LOG_NO": "",
                    "LOG_MSG_NO": "000000",
                    "MESSAGE_V1": "",
                    "MESSAGE_V2": "",
                    "MESSAGE_V3": "",
                    "MESSAGE_V4": "",
                    "PARAMETER": "",
                    "ROW": 0,
                    "FIELD": "",
                    "SYSTEM": ""
                },
                "WA_FRNCHSE": {
                    "NAME1": "JOHAR PERIPHERALS",
                    "J_1IPANNO": "ADAPJ4450A",
                    "HOUSE_NUM1": "1",
                    "STREET": "PROP  CHETAN JOHAR",
                    "CITY1": "RANCHI",
                    "POST_CODE1": "834002",
                    "LANDX": "India",
                    "TEL_NUMBER": "06512412778",
                    "SMTP_ADDR": "aeplranchi@yahoo.com",
                    "SERVICETAX": "",
                    "BANKN": "31755137083",
                    "BANKA": "State Bank Of India",
                    "REGIO": "20",
                    "BEZEI": "Jharkhand",
                    "IFSC": "SBIN0007957",
                    "STCD3": "20ADAPJ4450A2ZJ"
                }
            }
        }, status=200)

    except Exception as e:
        return Response({
            "code": 500,
            "status": "Error",
            "message": "Something went wrong while processing the request.",
            "error": str(e)
        }, status=500)

 
#Bapiii
@api_view(["POST"])
@permission_classes([AllowAny])
def all_store_detail(request):
    storeUID = request.data.get("storeUID")
    
    if not storeUID:
        return Response({"code": 400, "status": "Failure", "message": "StoreUID is required"}, status=400)

    try:
        # conn = Connection(ashost='172.22.224.9', sysnr='06', client='300', user='RFCUSER_ASP', passwd='Meridian@12345', lang='EN')
	    # print("Connection to SAP successful")
        # result = conn.call('ZBAPIFRANCHISE', LIFNR_VN=u'1301443')
        return Response({
            "code": 201,
            "status": "Success",
            "all_store_details": {
  "RETURN": {
    "TYPE": "",
    "ID": "",
    "NUMBER": "000",
    "MESSAGE": "",
    "LOG_NO": "",
    "LOG_MSG_NO": "000000",
    "MESSAGE_V1": "",
    "MESSAGE_V2": "",
    "MESSAGE_V3": "",
    "MESSAGE_V4": "",
    "PARAMETER": "",
    "ROW": 0,
    "FIELD": "",
    "SYSTEM": ""
  },
  "ALL_STORE": [
    {
      "KUNNR": "0000003078",
      "LEGACY_CODE": "0000003078",
      "NAME1": "Aditya Birla Fashion and Retai"
    },
    {
      "KUNNR": "0000003314",
      "LEGACY_CODE": "0000003314",
      "NAME1": "Aditya Birla Fashion and Retai"
    },
    {
      "KUNNR": "0000009802",
      "LEGACY_CODE": "0000009802",
      "NAME1": "Aditya Birla Fashion and Retai"
    },
    {
      "KUNNR": "0000009803",
      "LEGACY_CODE": "0000009803",
      "NAME1": "Aditya Birla Fashion and Retai"
    },
     {
      "KUNNR": "0000003380",
      "LEGACY_CODE": "0000003380",
      "NAME1": "Aditya Birla Fashion and Retai"
    }
  ]
}
        }, status=200)
        
        
    except Exception as e:
        return Response({"code": 500, "status": "Error", "message": "Error connecting to SAP:", "error": str(e)}, status=500)

    # finally:
    #     if conn:
    #         conn.close() 


#Bapiii   
@api_view(["POST"])
@permission_classes([AllowAny])
def ledger_detail(request):
    company = request.data.get("company")
    fromDate = request.data.get("fromDate")
    toDate = request.data.get("toDate")
    storeUID = request.data.get("storeUID")
    ledgerType = request.data.get("ledgerType")
    
    if not company or not fromDate or not toDate or not storeUID:
        return Response({"code": 400, "status": "Failure", "message": "company, from-date, to-date, storeUID is required"}, status=400)

    try:
        # con = Connection(ashost='172.22.224.9', sysnr='06', client='300', user='RFCUSER_ASP', passwd='Meridian@12345', lang='EN')
        # result = con.call('ZBAPI_LEDGER',BUKRS_CC=company, START_DATE=fromDate, END_DATE=toDate, LIFNR=storeUID)
        # json_data = json.dumps(result, use_decimal=True)
        json_data = json.dumps({'CLOSE_BALANCE': Decimal('26169.18'), 'OPEN_BALANCE': Decimal('36353.44'), 'RETURN': {'TYPE': '', 'ID': '', 'NUMBER': '000', 'MESSAGE': '', 'LOG_NO': '', 'LOG_MSG_NO': '000000', 'MESSAGE_V1': '', 'MESSAGE_V2': '', 'MESSAGE_V3': '', 'MESSAGE_V4': '', 'PARAMETER': '', 'ROW': 0, 'FIELD': '', 'SYSTEM': ''}, 'INT_LEDGER': [{'GJAHR': '2024', 'BUDAT': '20240610', 'BELNR': '1001647401', 'SHKZG': 'S', 'XBLNR': 'JP/ROK/24-25/006', 'SGTXT': '', 'GR_AMOUNT': Decimal('188.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('178.00'), 'NET_CREDIT': Decimal('0.00'), 'AUGBL': '1001647401', 'AUGDT': '20240610', 'BLART': 'AB', 'UMSKZ': '8', 'ZUONR': '20240610', 'STORE_CODE': '', 'STATE_CODE': '', 'HSN_SAC': '', 'PRCTR': 'HO', 'H_BLDAT': '20240610', 'FAEDT': '20240610', 'LTEXT': 'Accounting document', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240610', 'BELNR': '1001647403', 'SHKZG': 'S', 'XBLNR': '', 'SGTXT': '', 'GR_AMOUNT': Decimal('122464.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('116340.00'), 'NET_CREDIT': Decimal('0.00'), 'AUGBL': '1001647403', 'AUGDT': '20240610', 'BLART': 'AB', 'UMSKZ': '8', 'ZUONR': '20240610', 'STORE_CODE': '', 'STATE_CODE': '', 'HSN_SAC': '', 'PRCTR': 'HO', 'H_BLDAT': '20240610', 'FAEDT': '20240610', 'LTEXT': 'Accounting document', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240610', 'BELNR': '1900071144', 'SHKZG': 'H', 'XBLNR': 'JP/ROK/24-25/006', 'SGTXT': 'Virtual Comm-202405-LP-3314', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('33.84'), 'AUGBL': '2100034179', 'AUGDT': '20240612', 'BLART': 'KR', 'UMSKZ': '', 'ZUONR': '3314', 'STORE_CODE': '102123', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240606', 'FAEDT': '20240606', 'LTEXT': 'Vendor invoice - FI', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240610', 'BELNR': '1900071153', 'SHKZG': 'H', 'XBLNR': 'JP/ROK/24-25/004', 'SGTXT': 'VARI COMM-202405-LP-3314', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('22043.52'), 'AUGBL': '2100034179', 'AUGDT': '20240612', 'BLART': 'KR', 'UMSKZ': '', 'ZUONR': '3314', 'STORE_CODE': '102123', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240606', 'FAEDT': '20240606', 'LTEXT': 'Vendor invoice - FI', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240610', 'BELNR': '4600036773', 'SHKZG': 'H', 'XBLNR': 'JP/ROK/24-25/004', 'SGTXT': 'VARI COMM-202405-LP-3314', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('116340.80'), 'AUGBL': '2100034178', 'AUGDT': '20240612', 'BLART': 'ZK', 'UMSKZ': '', 'ZUONR': '3314', 'STORE_CODE': '102123', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240606', 'FAEDT': '20240606', 'LTEXT': 'Vendor 2 Vendor post', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240610', 'BELNR': '1001647401', 'SHKZG': 'H', 'XBLNR': 'JP/ROK/24-25/006', 'SGTXT': '', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('178.60'), 'AUGBL': '1001647401', 'AUGDT': '20240610', 'BLART': 'AB', 'UMSKZ': '8', 'ZUONR': '20240610', 'STORE_CODE': '', 'STATE_CODE': '', 'HSN_SAC': '', 'PRCTR': 'HO', 'H_BLDAT': '20240610', 'FAEDT': '20240610', 'LTEXT': 'Accounting document', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240610', 'BELNR': '4600036769', 'SHKZG': 'H', 'XBLNR': 'JP/ROK/24-25/006', 'SGTXT': 'Virtual Comm-202405-LP-3314', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('178.60'), 'AUGBL': '2100034178', 'AUGDT': '20240612', 'BLART': 'ZK', 'UMSKZ': '', 'ZUONR': '3314', 'STORE_CODE': '102123', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240606', 'FAEDT': '20240606', 'LTEXT': 'Vendor 2 Vendor post', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240610', 'BELNR': '1001647403', 'SHKZG': 'H', 'XBLNR': '', 'SGTXT': '', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('116340.80'), 'AUGBL': '1001647403', 'AUGDT': '20240610', 'BLART': 'AB', 'UMSKZ': '8', 'ZUONR': '20240610', 'STORE_CODE': '', 'STATE_CODE': '', 'HSN_SAC': '', 'PRCTR': 'HO', 'H_BLDAT': '20240610', 'FAEDT': '20240610', 'LTEXT': 'Accounting document', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240610', 'BELNR': '4600036769', 'SHKZG': 'S', 'XBLNR': 'JP/ROK/24-25/006', 'SGTXT': 'Virtual Comm-202405-LP-3314', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('178.60'), 'NET_CREDIT': Decimal('0.00'), 'AUGBL': '1001647401', 'AUGDT': '20240610', 'BLART': 'ZK', 'UMSKZ': '8', 'ZUONR': '3314', 'STORE_CODE': '102123', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240606', 'FAEDT': '20240606', 'LTEXT': 'Vendor 2 Vendor post', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240610', 'BELNR': '4600036773', 'SHKZG': 'S', 'XBLNR': 'JP/ROK/24-25/004', 'SGTXT': 'VARI COMM-202405-LP-3314', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('116340.80'), 'NET_CREDIT': Decimal('0.00'), 'AUGBL': '1001647403', 'AUGDT': '20240610', 'BLART': 'ZK', 'UMSKZ': '8', 'ZUONR': '3314', 'STORE_CODE': '102123', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240606', 'FAEDT': '20240606', 'LTEXT': 'Vendor 2 Vendor post', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240611', 'BELNR': '4600040642', 'SHKZG': 'H', 'XBLNR': 'VC-0524-9802', 'SGTXT': 'VARI COMM-202405-LP-9802', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('224054.00'), 'AUGBL': '2100034178', 'AUGDT': '20240612', 'BLART': 'ZK', 'UMSKZ': '', 'ZUONR': '9802', 'STORE_CODE': '9000278', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'LP', 'H_BLDAT': '20240611', 'FAEDT': '20240611', 'LTEXT': 'Vendor 2 Vendor post', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240612', 'BELNR': '4600041133', 'SHKZG': 'S', 'XBLNR': 'VC-0524-9802', 'SGTXT': 'VARI COMM-202405-LP-9802', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('224054.00'), 'NET_CREDIT': Decimal('0.00'), 'AUGBL': '1001846795', 'AUGDT': '20240619', 'BLART': 'ZK', 'UMSKZ': '', 'ZUONR': '9802', 'STORE_CODE': '9000278', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'LP', 'H_BLDAT': '20240612', 'FAEDT': '20240612', 'LTEXT': 'Vendor 2 Vendor post', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240614', 'BELNR': '4600039181', 'SHKZG': 'H', 'XBLNR': 'VC-0524-9802', 'SGTXT': 'VARI COMM-202405-LP-9802', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('224054.00'), 'AUGBL': '1600004981', 'AUGDT': '20240614', 'BLART': 'ZK', 'UMSKZ': '', 'ZUONR': '9802', 'STORE_CODE': '9000278', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'LP', 'H_BLDAT': '20240614', 'FAEDT': '20240614', 'LTEXT': 'Vendor 2 Vendor post', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240614', 'BELNR': '1600004981', 'SHKZG': 'S', 'XBLNR': 'VC-0524-9802', 'SGTXT': 'VARI COMM-202405-LP-9802', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('224054.00'), 'NET_CREDIT': Decimal('0.00'), 'AUGBL': '1600004981', 'AUGDT': '20240614', 'BLART': 'ZF', 'UMSKZ': '', 'ZUONR': '9802', 'STORE_CODE': '9000278', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'LP', 'H_BLDAT': '20240614', 'FAEDT': '20240614', 'LTEXT': 'Vendor 2 Vendor Reve', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240619', 'BELNR': '4600044814', 'SHKZG': 'H', 'XBLNR': 'JP/ROK/24-25/005', 'SGTXT': 'VARI COMM-202405-LP-9802', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('188364.10'), 'AUGBL': '1001846795', 'AUGDT': '20240619', 'BLART': 'ZK', 'UMSKZ': '', 'ZUONR': '9802', 'STORE_CODE': '9000278', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240606', 'FAEDT': '20240606', 'LTEXT': 'Vendor 2 Vendor post', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240619', 'BELNR': '4600044814', 'SHKZG': 'S', 'XBLNR': 'JP/ROK/24-25/005', 'SGTXT': 'VARI COMM-202405-LP-9802', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('188364.10'), 'NET_CREDIT': Decimal('0.00'), 'AUGBL': '1001846626', 'AUGDT': '20240619', 'BLART': 'ZK', 'UMSKZ': '8', 'ZUONR': '9802', 'STORE_CODE': '9000278', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240606', 'FAEDT': '20240606', 'LTEXT': 'Vendor 2 Vendor post', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240619', 'BELNR': '1001846795', 'SHKZG': 'S', 'XBLNR': '', 'SGTXT': '', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('35690.04'), 'NET_CREDIT': Decimal('0.00'), 'AUGBL': '1001846795', 'AUGDT': '20240619', 'BLART': 'AB', 'UMSKZ': '', 'ZUONR': '20240619', 'STORE_CODE': '', 'STATE_CODE': '', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240619', 'FAEDT': '20240619', 'LTEXT': 'Accounting document', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240619', 'BELNR': '1001846795', 'SHKZG': 'S', 'XBLNR': '', 'SGTXT': '', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('188364.10'), 'NET_CREDIT': Decimal('0.00'), 'AUGBL': '1001846795', 'AUGDT': '20240619', 'BLART': 'AB', 'UMSKZ': '', 'ZUONR': '20240619', 'STORE_CODE': '', 'STATE_CODE': '', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240619', 'FAEDT': '20240619', 'LTEXT': 'Accounting document', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240619', 'BELNR': '1001846626', 'SHKZG': 'H', 'XBLNR': '', 'SGTXT': '', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('188364.10'), 'AUGBL': '1001846626', 'AUGDT': '20240619', 'BLART': 'AB', 'UMSKZ': '8', 'ZUONR': '20240619', 'STORE_CODE': '', 'STATE_CODE': '', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240619', 'FAEDT': '20240619', 'LTEXT': 'Accounting document', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240619', 'BELNR': '1001846795', 'SHKZG': 'H', 'XBLNR': '', 'SGTXT': '', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('224054.00'), 'AUGBL': '1001846795', 'AUGDT': '20240619', 'BLART': 'AB', 'UMSKZ': '', 'ZUONR': '20240619', 'STORE_CODE': '', 'STATE_CODE': '', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240619', 'FAEDT': '20240619', 'LTEXT': 'Accounting document', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240619', 'BELNR': '1900078001', 'SHKZG': 'H', 'XBLNR': 'JP/ROK/24-25/005', 'SGTXT': 'VARI COMM-202405-LP-9802', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('35690.04'), 'AUGBL': '1001846795', 'AUGDT': '20240619', 'BLART': 'KR', 'UMSKZ': '', 'ZUONR': '9802', 'STORE_CODE': '9000278', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240606', 'FAEDT': '20240609', 'LTEXT': 'Vendor invoice - FI', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240619', 'BELNR': '1001846626', 'SHKZG': 'S', 'XBLNR': '', 'SGTXT': '', 'GR_AMOUNT': Decimal('198278.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('188364.00'), 'NET_CREDIT': Decimal('0.00'), 'AUGBL': '1001846626', 'AUGDT': '20240619', 'BLART': 'AB', 'UMSKZ': '8', 'ZUONR': '20240619', 'STORE_CODE': '', 'STATE_CODE': '', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240619', 'FAEDT': '20240619', 'LTEXT': 'Accounting document', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240630', 'BELNR': '1900093016', 'SHKZG': 'H', 'XBLNR': 'VC-0624-3314', 'SGTXT': 'VARI COMM-202406-LP-3314', 'GR_AMOUNT': Decimal('-158245.00'), 'TAX_AMOUNT': Decimal('-7913.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('150332.00'), 'AUGBL': '1002451156', 'AUGDT': '20240715', 'BLART': 'KR', 'UMSKZ': '8', 'ZUONR': '3314', 'STORE_CODE': '102123', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240630', 'FAEDT': '20240630', 'LTEXT': 'Vendor invoice - FI', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240630', 'BELNR': '1900093617', 'SHKZG': 'H', 'XBLNR': 'VC-0624-9802', 'SGTXT': 'VARI COMM-202406-LP-9802', 'GR_AMOUNT': Decimal('-226497.00'), 'TAX_AMOUNT': Decimal('-11325.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('215172.00'), 'AUGBL': '1003337755', 'AUGDT': '20240813', 'BLART': 'KR', 'UMSKZ': '8', 'ZUONR': '9802', 'STORE_CODE': '9000278', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240630', 'FAEDT': '20240630', 'LTEXT': 'Vendor invoice - FI', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240630', 'BELNR': '6500582188', 'SHKZG': 'S', 'XBLNR': 'MSDR242100000471', 'SGTXT': '980203.06.20241064.5400.150.381256.7', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('1256.70'), 'NET_CREDIT': Decimal('0.00'), 'AUGBL': '2100048247', 'AUGDT': '20240712', 'BLART': 'YV', 'UMSKZ': '', 'ZUONR': 'Q9000278OD', 'STORE_CODE': 'NA', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HO', 'H_BLDAT': '20240630', 'FAEDT': '20240630', 'LTEXT': 'Trnsf btn Cust 2 VeN', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240630', 'BELNR': '6500601311', 'SHKZG': 'S', 'XBLNR': 'MSDR242100000531', 'SGTXT': 'CC charges-202406-3314', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('1113.92'), 'NET_CREDIT': Decimal('0.00'), 'AUGBL': '2100048247', 'AUGDT': '20240712', 'BLART': 'YV', 'UMSKZ': '', 'ZUONR': 'Q102123OD', 'STORE_CODE': 'NA', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HO', 'H_BLDAT': '20240630', 'FAEDT': '20240630', 'LTEXT': 'Trnsf btn Cust 2 VeN', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240630', 'BELNR': '6500600904', 'SHKZG': 'S', 'XBLNR': 'MSDR242100000510', 'SGTXT': 'CC charges-202406-9802', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('1196.52'), 'NET_CREDIT': Decimal('0.00'), 'AUGBL': '2100048247', 'AUGDT': '20240712', 'BLART': 'YV', 'UMSKZ': '', 'ZUONR': 'Q9000278OD', 'STORE_CODE': 'NA', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HO', 'H_BLDAT': '20240630', 'FAEDT': '20240630', 'LTEXT': 'Trnsf btn Cust 2 VeN', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240710', 'BELNR': '4600054961', 'SHKZG': 'H', 'XBLNR': 'VC-0624-9802', 'SGTXT': 'VARI COMM-202406-LP-9802', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('255941.00'), 'AUGBL': '2100048247', 'AUGDT': '20240712', 'BLART': 'ZK', 'UMSKZ': '', 'ZUONR': '9802', 'STORE_CODE': '9000278', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'LP', 'H_BLDAT': '20240710', 'FAEDT': '20240710', 'LTEXT': 'Vendor 2 Vendor post', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240710', 'BELNR': '4600054960', 'SHKZG': 'H', 'XBLNR': 'VC-0624-3314', 'SGTXT': 'VARI COMM-202406-LP-3314', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('178816.00'), 'AUGBL': '2100048247', 'AUGDT': '20240712', 'BLART': 'ZK', 'UMSKZ': '', 'ZUONR': '3314', 'STORE_CODE': '102123', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'LP', 'H_BLDAT': '20240710', 'FAEDT': '20240710', 'LTEXT': 'Vendor 2 Vendor post', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240710', 'BELNR': '4600057201', 'SHKZG': 'S', 'XBLNR': 'VC-0624-3314', 'SGTXT': 'VARI COMM-202406-LP-3314', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('178816.00'), 'NET_CREDIT': Decimal('0.00'), 'AUGBL': '1002479590', 'AUGDT': '20240715', 'BLART': 'ZK', 'UMSKZ': '', 'ZUONR': '3314', 'STORE_CODE': '102123', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'LP', 'H_BLDAT': '20240710', 'FAEDT': '20240710', 'LTEXT': 'Vendor 2 Vendor post', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240710', 'BELNR': '4600057202', 'SHKZG': 'S', 'XBLNR': 'VC-0624-9802', 'SGTXT': 'VARI COMM-202406-LP-9802', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('255941.00'), 'NET_CREDIT': Decimal('0.00'), 'AUGBL': '1003379241', 'AUGDT': '20240813', 'BLART': 'ZK', 'UMSKZ': '', 'ZUONR': '9802', 'STORE_CODE': '9000278', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'LP', 'H_BLDAT': '20240710', 'FAEDT': '20240710', 'LTEXT': 'Vendor 2 Vendor post', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240715', 'BELNR': '1002479590', 'SHKZG': 'S', 'XBLNR': '', 'SGTXT': '', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('28484.10'), 'NET_CREDIT': Decimal('0.00'), 'AUGBL': '1002479590', 'AUGDT': '20240715', 'BLART': 'AB', 'UMSKZ': '', 'ZUONR': '20240715', 'STORE_CODE': '', 'STATE_CODE': '', 'HSN_SAC': '', 'PRCTR': 'HO', 'H_BLDAT': '20240715', 'FAEDT': '20240715', 'LTEXT': 'Accounting document', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240715', 'BELNR': '1002479590', 'SHKZG': 'S', 'XBLNR': '', 'SGTXT': '', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('150332.75'), 'NET_CREDIT': Decimal('0.00'), 'AUGBL': '1002479590', 'AUGDT': '20240715', 'BLART': 'AB', 'UMSKZ': '', 'ZUONR': '20240715', 'STORE_CODE': '', 'STATE_CODE': '', 'HSN_SAC': '', 'PRCTR': 'HO', 'H_BLDAT': '20240715', 'FAEDT': '20240715', 'LTEXT': 'Accounting document', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240715', 'BELNR': '1002451156', 'SHKZG': 'H', 'XBLNR': '', 'SGTXT': '', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('150332.75'), 'AUGBL': '1002451156', 'AUGDT': '20240715', 'BLART': 'AB', 'UMSKZ': '8', 'ZUONR': '20240715', 'STORE_CODE': '', 'STATE_CODE': '', 'HSN_SAC': '', 'PRCTR': 'HO', 'H_BLDAT': '20240715', 'FAEDT': '20240715', 'LTEXT': 'Accounting document', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240715', 'BELNR': '1002479590', 'SHKZG': 'H', 'XBLNR': '', 'SGTXT': '', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('178816.00'), 'AUGBL': '1002479590', 'AUGDT': '20240715', 'BLART': 'AB', 'UMSKZ': '', 'ZUONR': '20240715', 'STORE_CODE': '', 'STATE_CODE': '', 'HSN_SAC': '', 'PRCTR': 'HO', 'H_BLDAT': '20240715', 'FAEDT': '20240715', 'LTEXT': 'Accounting document', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240715', 'BELNR': '4600060247', 'SHKZG': 'H', 'XBLNR': 'JP/ROK/24-25/007', 'SGTXT': 'VARI COMM-202406-LP-3314', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('150332.75'), 'AUGBL': '1002479590', 'AUGDT': '20240715', 'BLART': 'ZK', 'UMSKZ': '', 'ZUONR': '3314', 'STORE_CODE': '102123', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240704', 'FAEDT': '20240704', 'LTEXT': 'Vendor 2 Vendor post', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240715', 'BELNR': '4600060247', 'SHKZG': 'S', 'XBLNR': 'JP/ROK/24-25/007', 'SGTXT': 'VARI COMM-202406-LP-3314', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('150332.75'), 'NET_CREDIT': Decimal('0.00'), 'AUGBL': '1002451156', 'AUGDT': '20240715', 'BLART': 'ZK', 'UMSKZ': '8', 'ZUONR': '3314', 'STORE_CODE': '102123', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240704', 'FAEDT': '20240704', 'LTEXT': 'Vendor 2 Vendor post', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240715', 'BELNR': '1900104606', 'SHKZG': 'H', 'XBLNR': 'JP/ROK/24-25/007', 'SGTXT': 'VARI COMM-202406-LP-3314', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('28484.10'), 'AUGBL': '1002479590', 'AUGDT': '20240715', 'BLART': 'KR', 'UMSKZ': '', 'ZUONR': '3314', 'STORE_CODE': '102123', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240704', 'FAEDT': '20240707', 'LTEXT': 'Vendor invoice - FI', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240715', 'BELNR': '1002451156', 'SHKZG': 'S', 'XBLNR': '', 'SGTXT': '', 'GR_AMOUNT': Decimal('-158245.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('150332.00'), 'NET_CREDIT': Decimal('0.00'), 'AUGBL': '1002451156', 'AUGDT': '20240715', 'BLART': 'AB', 'UMSKZ': '8', 'ZUONR': '20240715', 'STORE_CODE': '', 'STATE_CODE': '', 'HSN_SAC': '', 'PRCTR': 'HO', 'H_BLDAT': '20240715', 'FAEDT': '20240715', 'LTEXT': 'Accounting document', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240731', 'BELNR': '1900125572', 'SHKZG': 'H', 'XBLNR': 'VC-0724-9802', 'SGTXT': 'VARI COMM-202407-LP-9802', 'GR_AMOUNT': Decimal('-181838.00'), 'TAX_AMOUNT': Decimal('-9092.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('172746.00'), 'AUGBL': '1003337753', 'AUGDT': '20240813', 'BLART': 'KR', 'UMSKZ': '8', 'ZUONR': '9802', 'STORE_CODE': '9000278', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240731', 'FAEDT': '20240731', 'LTEXT': 'Vendor invoice - FI', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240731', 'BELNR': '1900123935', 'SHKZG': 'H', 'XBLNR': 'VC-0724-3314', 'SGTXT': 'VARI COMM-202407-LP-3314', 'GR_AMOUNT': Decimal('-132065.00'), 'TAX_AMOUNT': Decimal('-6604.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('125461.00'), 'AUGBL': '1003379151', 'AUGDT': '20240814', 'BLART': 'KR', 'UMSKZ': '8', 'ZUONR': '3314', 'STORE_CODE': '102123', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240731', 'FAEDT': '20240731', 'LTEXT': 'Vendor invoice - FI', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240731', 'BELNR': '1900125703', 'SHKZG': 'H', 'XBLNR': "JUL'24-3314", 'SGTXT': 'Virtual Comm-202407-LP-3314', 'GR_AMOUNT': Decimal('-227.00'), 'TAX_AMOUNT': Decimal('-12.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('215.00'), 'AUGBL': '1003379151', 'AUGDT': '20240814', 'BLART': 'KR', 'UMSKZ': '8', 'ZUONR': '3314', 'STORE_CODE': '102123', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240731', 'FAEDT': '20240731', 'LTEXT': 'Vendor invoice - FI', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240731', 'BELNR': '6500769534', 'SHKZG': 'S', 'XBLNR': 'MSDR242100000690', 'SGTXT': 'CC charges-202407-9802', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('1089.14'), 'NET_CREDIT': Decimal('0.00'), 'AUGBL': '2100062777', 'AUGDT': '20240814', 'BLART': 'YV', 'UMSKZ': '', 'ZUONR': 'Q9000278OD', 'STORE_CODE': 'NA', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HO', 'H_BLDAT': '20240731', 'FAEDT': '20240731', 'LTEXT': 'Trnsf btn Cust 2 VeN', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240731', 'BELNR': '6500767911', 'SHKZG': 'S', 'XBLNR': 'MSDR242100000656', 'SGTXT': 'CC charges-202407-3314', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('1511.58'), 'NET_CREDIT': Decimal('0.00'), 'AUGBL': '2100063939', 'AUGDT': '20240819', 'BLART': 'YV', 'UMSKZ': '', 'ZUONR': 'Q102123OD', 'STORE_CODE': 'NA', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HO', 'H_BLDAT': '20240731', 'FAEDT': '20240731', 'LTEXT': 'Trnsf btn Cust 2 VeN', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240809', 'BELNR': '1600006880', 'SHKZG': 'S', 'XBLNR': 'VC-0724-9802', 'SGTXT': 'VARI COMM-202407-LP-9802', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('205477.00'), 'NET_CREDIT': Decimal('0.00'), 'AUGBL': '1600006880', 'AUGDT': '20240809', 'BLART': 'ZF', 'UMSKZ': '', 'ZUONR': '9802', 'STORE_CODE': '9000278', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'LP', 'H_BLDAT': '20240809', 'FAEDT': '20240809', 'LTEXT': 'Vendor 2 Vendor Reve', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240809', 'BELNR': '4600070233', 'SHKZG': 'H', 'XBLNR': 'VC-0724-9802', 'SGTXT': 'VARI COMM-202407-LP-9802', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('205477.00'), 'AUGBL': '1600006880', 'AUGDT': '20240809', 'BLART': 'ZK', 'UMSKZ': '', 'ZUONR': '9802', 'STORE_CODE': '9000278', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'LP', 'H_BLDAT': '20240809', 'FAEDT': '20240809', 'LTEXT': 'Vendor 2 Vendor post', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240812', 'BELNR': '1003379241', 'SHKZG': 'H', 'XBLNR': '', 'SGTXT': '', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('255941.00'), 'AUGBL': '1003379241', 'AUGDT': '20240813', 'BLART': 'AB', 'UMSKZ': '', 'ZUONR': '20240812', 'STORE_CODE': '', 'STATE_CODE': '', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240812', 'FAEDT': '20240812', 'LTEXT': 'Accounting document', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240812', 'BELNR': '1003379241', 'SHKZG': 'S', 'XBLNR': '', 'SGTXT': '', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('215172.15'), 'NET_CREDIT': Decimal('0.00'), 'AUGBL': '1003379241', 'AUGDT': '20240813', 'BLART': 'AB', 'UMSKZ': '', 'ZUONR': '20240812', 'STORE_CODE': '', 'STATE_CODE': '', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240812', 'FAEDT': '20240812', 'LTEXT': 'Accounting document', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240812', 'BELNR': '1003379241', 'SHKZG': 'S', 'XBLNR': '', 'SGTXT': '', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('40769.46'), 'NET_CREDIT': Decimal('0.00'), 'AUGBL': '1003379241', 'AUGDT': '20240813', 'BLART': 'AB', 'UMSKZ': '', 'ZUONR': '20240812', 'STORE_CODE': '', 'STATE_CODE': '', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240812', 'FAEDT': '20240812', 'LTEXT': 'Accounting document', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240813', 'BELNR': '1003337755', 'SHKZG': 'H', 'XBLNR': '', 'SGTXT': '', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('215172.15'), 'AUGBL': '1003337755', 'AUGDT': '20240813', 'BLART': 'AB', 'UMSKZ': '8', 'ZUONR': '20240813', 'STORE_CODE': '', 'STATE_CODE': '', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240813', 'FAEDT': '20240813', 'LTEXT': 'Accounting document', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240813', 'BELNR': '1003337753', 'SHKZG': 'H', 'XBLNR': '', 'SGTXT': '', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('172746.10'), 'AUGBL': '1003337753', 'AUGDT': '20240813', 'BLART': 'AB', 'UMSKZ': '8', 'ZUONR': '20240813', 'STORE_CODE': '', 'STATE_CODE': '', 'HSN_SAC': '', 'PRCTR': 'HO', 'H_BLDAT': '20240813', 'FAEDT': '20240813', 'LTEXT': 'Accounting document', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240813', 'BELNR': '1900132044', 'SHKZG': 'H', 'XBLNR': 'JP/ROK/24-25/008', 'SGTXT': 'VARI COMM-202406-LP-9802', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('40769.46'), 'AUGBL': '1003379241', 'AUGDT': '20240813', 'BLART': 'KR', 'UMSKZ': '', 'ZUONR': '9802', 'STORE_CODE': '9000278', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240704', 'FAEDT': '20240707', 'LTEXT': 'Vendor invoice - FI', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240813', 'BELNR': '4600074714', 'SHKZG': 'H', 'XBLNR': 'JP/ROK/24-25/008', 'SGTXT': 'VARI COMM-202406-LP-9802', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('215172.15'), 'AUGBL': '1003379241', 'AUGDT': '20240813', 'BLART': 'ZK', 'UMSKZ': '', 'ZUONR': '9802', 'STORE_CODE': '9000278', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240704', 'FAEDT': '20240704', 'LTEXT': 'Vendor 2 Vendor post', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240813', 'BELNR': '1003337753', 'SHKZG': 'S', 'XBLNR': '', 'SGTXT': '', 'GR_AMOUNT': Decimal('-181838.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('172746.00'), 'NET_CREDIT': Decimal('0.00'), 'AUGBL': '1003337753', 'AUGDT': '20240813', 'BLART': 'AB', 'UMSKZ': '8', 'ZUONR': '20240813', 'STORE_CODE': '', 'STATE_CODE': '', 'HSN_SAC': '', 'PRCTR': 'HO', 'H_BLDAT': '20240813', 'FAEDT': '20240813', 'LTEXT': 'Accounting document', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240813', 'BELNR': '4600074714', 'SHKZG': 'S', 'XBLNR': 'JP/ROK/24-25/008', 'SGTXT': 'VARI COMM-202406-LP-9802', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('215172.15'), 'NET_CREDIT': Decimal('0.00'), 'AUGBL': '1003337755', 'AUGDT': '20240813', 'BLART': 'ZK', 'UMSKZ': '8', 'ZUONR': '9802', 'STORE_CODE': '9000278', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240704', 'FAEDT': '20240704', 'LTEXT': 'Vendor 2 Vendor post', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240813', 'BELNR': '1003337755', 'SHKZG': 'S', 'XBLNR': '', 'SGTXT': '', 'GR_AMOUNT': Decimal('-226497.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('215172.00'), 'NET_CREDIT': Decimal('0.00'), 'AUGBL': '1003337755', 'AUGDT': '20240813', 'BLART': 'AB', 'UMSKZ': '8', 'ZUONR': '20240813', 'STORE_CODE': '', 'STATE_CODE': '', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240813', 'FAEDT': '20240813', 'LTEXT': 'Accounting document', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240813', 'BELNR': '1900132038', 'SHKZG': 'H', 'XBLNR': 'JP/ROK/24-25/010', 'SGTXT': 'VARI COMM-202407-LP-9802', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('32730.84'), 'AUGBL': '2100062778', 'AUGDT': '20240814', 'BLART': 'KR', 'UMSKZ': '', 'ZUONR': '9802', 'STORE_CODE': '9000278', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240806', 'FAEDT': '20240806', 'LTEXT': 'Vendor invoice - FI', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240813', 'BELNR': '4600074709', 'SHKZG': 'H', 'XBLNR': 'JP/ROK/24-25/010', 'SGTXT': 'VARI COMM-202407-LP-9802', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('172746.10'), 'AUGBL': '2100062777', 'AUGDT': '20240814', 'BLART': 'ZK', 'UMSKZ': '', 'ZUONR': '9802', 'STORE_CODE': '9000278', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240806', 'FAEDT': '20240806', 'LTEXT': 'Vendor 2 Vendor post', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240813', 'BELNR': '4600074709', 'SHKZG': 'S', 'XBLNR': 'JP/ROK/24-25/010', 'SGTXT': 'VARI COMM-202407-LP-9802', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('172746.10'), 'NET_CREDIT': Decimal('0.00'), 'AUGBL': '1003337753', 'AUGDT': '20240813', 'BLART': 'ZK', 'UMSKZ': '8', 'ZUONR': '9802', 'STORE_CODE': '9000278', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240806', 'FAEDT': '20240806', 'LTEXT': 'Vendor 2 Vendor post', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240814', 'BELNR': '1003379151', 'SHKZG': 'S', 'XBLNR': '', 'SGTXT': '', 'GR_AMOUNT': Decimal('-132292.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('125676.00'), 'NET_CREDIT': Decimal('0.00'), 'AUGBL': '1003379151', 'AUGDT': '20240814', 'BLART': 'AB', 'UMSKZ': '8', 'ZUONR': '20240814', 'STORE_CODE': '', 'STATE_CODE': '', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240814', 'FAEDT': '20240814', 'LTEXT': 'Accounting document', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240814', 'BELNR': '4600075563', 'SHKZG': 'H', 'XBLNR': 'JP/ROK/24-25/009', 'SGTXT': 'VARI COMM-202407-LP-3314', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('125461.75'), 'AUGBL': '2100063939', 'AUGDT': '20240819', 'BLART': 'ZK', 'UMSKZ': '', 'ZUONR': '3314', 'STORE_CODE': '102123', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240806', 'FAEDT': '20240806', 'LTEXT': 'Vendor 2 Vendor post', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240814', 'BELNR': '4600075556', 'SHKZG': 'S', 'XBLNR': 'JP/ROK/24-25/011', 'SGTXT': 'Virtual Comm-202407-LP-3314', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('215.65'), 'NET_CREDIT': Decimal('0.00'), 'AUGBL': '1003379151', 'AUGDT': '20240814', 'BLART': 'ZK', 'UMSKZ': '8', 'ZUONR': '3314', 'STORE_CODE': '102123', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240806', 'FAEDT': '20240806', 'LTEXT': 'Vendor 2 Vendor post', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240814', 'BELNR': '4600075563', 'SHKZG': 'S', 'XBLNR': 'JP/ROK/24-25/009', 'SGTXT': 'VARI COMM-202407-LP-3314', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('125461.75'), 'NET_CREDIT': Decimal('0.00'), 'AUGBL': '1003379151', 'AUGDT': '20240814', 'BLART': 'ZK', 'UMSKZ': '8', 'ZUONR': '3314', 'STORE_CODE': '102123', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240806', 'FAEDT': '20240806', 'LTEXT': 'Vendor 2 Vendor post', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240814', 'BELNR': '1003379151', 'SHKZG': 'H', 'XBLNR': '', 'SGTXT': '', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('125677.40'), 'AUGBL': '1003379151', 'AUGDT': '20240814', 'BLART': 'AB', 'UMSKZ': '8', 'ZUONR': '20240814', 'STORE_CODE': '', 'STATE_CODE': '', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240814', 'FAEDT': '20240814', 'LTEXT': 'Accounting document', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240814', 'BELNR': '4600075556', 'SHKZG': 'H', 'XBLNR': 'JP/ROK/24-25/011', 'SGTXT': 'Virtual Comm-202407-LP-3314', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('215.65'), 'AUGBL': '2100063939', 'AUGDT': '20240819', 'BLART': 'ZK', 'UMSKZ': '', 'ZUONR': '3314', 'STORE_CODE': '102123', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240806', 'FAEDT': '20240806', 'LTEXT': 'Vendor 2 Vendor post', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240814', 'BELNR': '1900133327', 'SHKZG': 'H', 'XBLNR': 'JP/ROK/24-25/011', 'SGTXT': 'Virtual Comm-202407-LP-3314', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('40.86'), 'AUGBL': '2100063940', 'AUGDT': '20240819', 'BLART': 'KR', 'UMSKZ': '', 'ZUONR': '3314', 'STORE_CODE': '102123', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240806', 'FAEDT': '20240806', 'LTEXT': 'Vendor invoice - FI', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240814', 'BELNR': '1900133339', 'SHKZG': 'H', 'XBLNR': 'JP/ROK/24-25/009', 'SGTXT': 'VARI COMM-202407-LP-3314', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('23771.70'), 'AUGBL': '2100063940', 'AUGDT': '20240819', 'BLART': 'KR', 'UMSKZ': '', 'ZUONR': '3314', 'STORE_CODE': '102123', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240806', 'FAEDT': '20240806', 'LTEXT': 'Vendor invoice - FI', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240831', 'BELNR': '1900148988', 'SHKZG': 'H', 'XBLNR': 'VC-0824-3314', 'SGTXT': 'VARI COMM-202408-LP-3314', 'GR_AMOUNT': Decimal('-111956.00'), 'TAX_AMOUNT': Decimal('-5598.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('106358.00'), 'AUGBL': '1004028927', 'AUGDT': '20240911', 'BLART': 'KR', 'UMSKZ': '8', 'ZUONR': '3314', 'STORE_CODE': '102123', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240831', 'FAEDT': '20240831', 'LTEXT': 'Vendor invoice - FI', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240831', 'BELNR': '6500937305', 'SHKZG': 'S', 'XBLNR': 'MSDR242100000801', 'SGTXT': 'CC charges-202408-9802', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('794.14'), 'NET_CREDIT': Decimal('0.00'), 'AUGBL': '2100073460', 'AUGDT': '20240909', 'BLART': 'YV', 'UMSKZ': '', 'ZUONR': 'Q9000278OD', 'STORE_CODE': 'NA', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HO', 'H_BLDAT': '20240831', 'FAEDT': '20240831', 'LTEXT': 'Trnsf btn Cust 2 VeN', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240831', 'BELNR': '1900150195', 'SHKZG': 'H', 'XBLNR': 'VC-0824-9802', 'SGTXT': 'VARI COMM-202408-LP-9802', 'GR_AMOUNT': Decimal('-135025.00'), 'TAX_AMOUNT': Decimal('-6752.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('128273.00'), 'AUGBL': '1004028788', 'AUGDT': '20240911', 'BLART': 'KR', 'UMSKZ': '8', 'ZUONR': '9802', 'STORE_CODE': '9000278', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240831', 'FAEDT': '20240831', 'LTEXT': 'Vendor invoice - FI', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240831', 'BELNR': '6500935713', 'SHKZG': 'S', 'XBLNR': 'MSDR242100000769', 'SGTXT': 'CC charges-202408-3314', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('712.72'), 'NET_CREDIT': Decimal('0.00'), 'AUGBL': '2100075764', 'AUGDT': '20240912', 'BLART': 'YV', 'UMSKZ': '', 'ZUONR': 'Q102123OD', 'STORE_CODE': 'NA', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HO', 'H_BLDAT': '20240831', 'FAEDT': '20240831', 'LTEXT': 'Trnsf btn Cust 2 VeN', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240831', 'BELNR': '1900148727', 'SHKZG': 'H', 'XBLNR': "AUG'24-3314", 'SGTXT': 'Virtual Comm-202408-LP-3314', 'GR_AMOUNT': Decimal('-526.00'), 'TAX_AMOUNT': Decimal('-27.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('499.00'), 'AUGBL': '1004029067', 'AUGDT': '20240911', 'BLART': 'KR', 'UMSKZ': '8', 'ZUONR': '3314', 'STORE_CODE': '102123', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240831', 'FAEDT': '20240831', 'LTEXT': 'Vendor invoice - FI', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240908', 'BELNR': '4600086378', 'SHKZG': 'H', 'XBLNR': 'VC-0824-9802', 'SGTXT': 'VARI COMM-202408-LP-9802', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('152578.00'), 'AUGBL': '2100073460', 'AUGDT': '20240909', 'BLART': 'ZK', 'UMSKZ': '', 'ZUONR': '9802', 'STORE_CODE': '9000278', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'LP', 'H_BLDAT': '20240908', 'FAEDT': '20240908', 'LTEXT': 'Vendor 2 Vendor post', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240909', 'BELNR': '4600088686', 'SHKZG': 'S', 'XBLNR': 'VC-0824-9802', 'SGTXT': 'VARI COMM-202408-LP-9802', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('152578.00'), 'NET_CREDIT': Decimal('0.00'), 'AUGBL': '1004511237', 'AUGDT': '20240914', 'BLART': 'ZK', 'UMSKZ': '', 'ZUONR': '9802', 'STORE_CODE': '9000278', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'LP', 'H_BLDAT': '20240909', 'FAEDT': '20240909', 'LTEXT': 'Vendor 2 Vendor post', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240911', 'BELNR': '1004028927', 'SHKZG': 'H', 'XBLNR': '', 'SGTXT': '', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('106358.20'), 'AUGBL': '1004028927', 'AUGDT': '20240911', 'BLART': 'AB', 'UMSKZ': '8', 'ZUONR': '20240911', 'STORE_CODE': '', 'STATE_CODE': '', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240911', 'FAEDT': '20240911', 'LTEXT': 'Accounting document', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240911', 'BELNR': '1004029067', 'SHKZG': 'H', 'XBLNR': 'JP/ROK/24-25/013', 'SGTXT': '', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('499.70'), 'AUGBL': '1004029067', 'AUGDT': '20240911', 'BLART': 'AB', 'UMSKZ': '8', 'ZUONR': '20240911', 'STORE_CODE': '', 'STATE_CODE': '', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240911', 'FAEDT': '20240911', 'LTEXT': 'Accounting document', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240911', 'BELNR': '1004029067', 'SHKZG': 'S', 'XBLNR': 'JP/ROK/24-25/013', 'SGTXT': '', 'GR_AMOUNT': Decimal('-526.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('499.00'), 'NET_CREDIT': Decimal('0.00'), 'AUGBL': '1004029067', 'AUGDT': '20240911', 'BLART': 'AB', 'UMSKZ': '8', 'ZUONR': '20240911', 'STORE_CODE': '', 'STATE_CODE': '', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240911', 'FAEDT': '20240911', 'LTEXT': 'Accounting document', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240911', 'BELNR': '1004028788', 'SHKZG': 'H', 'XBLNR': '', 'SGTXT': '', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('128273.75'), 'AUGBL': '1004028788', 'AUGDT': '20240911', 'BLART': 'AB', 'UMSKZ': '8', 'ZUONR': '20240911', 'STORE_CODE': '', 'STATE_CODE': '', 'HSN_SAC': '', 'PRCTR': 'HO', 'H_BLDAT': '20240911', 'FAEDT': '20240911', 'LTEXT': 'Accounting document', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240911', 'BELNR': '4600091082', 'SHKZG': 'H', 'XBLNR': 'JP/ROK/24-25/012', 'SGTXT': 'VARI COMM-202408-LP-3314', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('106358.20'), 'AUGBL': '2100075764', 'AUGDT': '20240912', 'BLART': 'ZK', 'UMSKZ': '', 'ZUONR': '3314', 'STORE_CODE': '102123', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240905', 'FAEDT': '20240905', 'LTEXT': 'Vendor 2 Vendor post', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240911', 'BELNR': '1004028788', 'SHKZG': 'S', 'XBLNR': '', 'SGTXT': '', 'GR_AMOUNT': Decimal('-135025.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('128273.00'), 'NET_CREDIT': Decimal('0.00'), 'AUGBL': '1004028788', 'AUGDT': '20240911', 'BLART': 'AB', 'UMSKZ': '8', 'ZUONR': '20240911', 'STORE_CODE': '', 'STATE_CODE': '', 'HSN_SAC': '', 'PRCTR': 'HO', 'H_BLDAT': '20240911', 'FAEDT': '20240911', 'LTEXT': 'Accounting document', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240911', 'BELNR': '4600091234', 'SHKZG': 'H', 'XBLNR': 'JP/ROK/24-25/013', 'SGTXT': 'Virtual Comm-202408-LP-3314', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('499.70'), 'AUGBL': '2100075764', 'AUGDT': '20240912', 'BLART': 'ZK', 'UMSKZ': '', 'ZUONR': '3314', 'STORE_CODE': '102123', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240905', 'FAEDT': '20240905', 'LTEXT': 'Vendor 2 Vendor post', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240911', 'BELNR': '1900156447', 'SHKZG': 'H', 'XBLNR': 'JP/ROK/24-25/013', 'SGTXT': 'Virtual Comm-202408-LP-3314', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('94.68'), 'AUGBL': '2100075765', 'AUGDT': '20240912', 'BLART': 'KR', 'UMSKZ': '', 'ZUONR': '3314', 'STORE_CODE': '102123', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240905', 'FAEDT': '20240905', 'LTEXT': 'Vendor invoice - FI', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240911', 'BELNR': '1900155781', 'SHKZG': 'H', 'XBLNR': 'JP/ROK/24-25/012', 'SGTXT': 'VARI COMM-202408-LP-3314', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('20152.08'), 'AUGBL': '2100075765', 'AUGDT': '20240912', 'BLART': 'KR', 'UMSKZ': '', 'ZUONR': '3314', 'STORE_CODE': '102123', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240905', 'FAEDT': '20240905', 'LTEXT': 'Vendor invoice - FI', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240911', 'BELNR': '1900155460', 'SHKZG': 'H', 'XBLNR': 'JP/ROK/24-25/014', 'SGTXT': 'VARI COMM-202408-LP-9802', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('24304.50'), 'AUGBL': '1004511237', 'AUGDT': '20240914', 'BLART': 'KR', 'UMSKZ': '', 'ZUONR': '9802', 'STORE_CODE': '9000278', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240905', 'FAEDT': '20240908', 'LTEXT': 'Vendor invoice - FI', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240911', 'BELNR': '1004028927', 'SHKZG': 'S', 'XBLNR': '', 'SGTXT': '', 'GR_AMOUNT': Decimal('-111956.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('106358.00'), 'NET_CREDIT': Decimal('0.00'), 'AUGBL': '1004028927', 'AUGDT': '20240911', 'BLART': 'AB', 'UMSKZ': '8', 'ZUONR': '20240911', 'STORE_CODE': '', 'STATE_CODE': '', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240911', 'FAEDT': '20240911', 'LTEXT': 'Accounting document', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240911', 'BELNR': '4600090744', 'SHKZG': 'H', 'XBLNR': 'JP/ROK/24-25/014', 'SGTXT': 'VARI COMM-202408-LP-9802', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('128273.75'), 'AUGBL': '1004511237', 'AUGDT': '20240914', 'BLART': 'ZK', 'UMSKZ': '', 'ZUONR': '9802', 'STORE_CODE': '9000278', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240905', 'FAEDT': '20240905', 'LTEXT': 'Vendor 2 Vendor post', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240911', 'BELNR': '4600091082', 'SHKZG': 'S', 'XBLNR': 'JP/ROK/24-25/012', 'SGTXT': 'VARI COMM-202408-LP-3314', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('106358.20'), 'NET_CREDIT': Decimal('0.00'), 'AUGBL': '1004028927', 'AUGDT': '20240911', 'BLART': 'ZK', 'UMSKZ': '8', 'ZUONR': '3314', 'STORE_CODE': '102123', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240905', 'FAEDT': '20240905', 'LTEXT': 'Vendor 2 Vendor post', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240911', 'BELNR': '4600091234', 'SHKZG': 'S', 'XBLNR': 'JP/ROK/24-25/013', 'SGTXT': 'Virtual Comm-202408-LP-3314', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('499.70'), 'NET_CREDIT': Decimal('0.00'), 'AUGBL': '1004029067', 'AUGDT': '20240911', 'BLART': 'ZK', 'UMSKZ': '8', 'ZUONR': '3314', 'STORE_CODE': '102123', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240905', 'FAEDT': '20240905', 'LTEXT': 'Vendor 2 Vendor post', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240911', 'BELNR': '4600090744', 'SHKZG': 'S', 'XBLNR': 'JP/ROK/24-25/014', 'SGTXT': 'VARI COMM-202408-LP-9802', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('128273.75'), 'NET_CREDIT': Decimal('0.00'), 'AUGBL': '1004028788', 'AUGDT': '20240911', 'BLART': 'ZK', 'UMSKZ': '8', 'ZUONR': '9802', 'STORE_CODE': '9000278', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240905', 'FAEDT': '20240905', 'LTEXT': 'Vendor 2 Vendor post', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240914', 'BELNR': '1004511237', 'SHKZG': 'H', 'XBLNR': '', 'SGTXT': '', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('152578.00'), 'AUGBL': '1004511237', 'AUGDT': '20240914', 'BLART': 'AB', 'UMSKZ': '', 'ZUONR': '20240914', 'STORE_CODE': '', 'STATE_CODE': '', 'HSN_SAC': '', 'PRCTR': 'HO', 'H_BLDAT': '20240914', 'FAEDT': '20240914', 'LTEXT': 'Accounting document', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240914', 'BELNR': '1004511237', 'SHKZG': 'S', 'XBLNR': '', 'SGTXT': '', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('128273.75'), 'NET_CREDIT': Decimal('0.00'), 'AUGBL': '1004511237', 'AUGDT': '20240914', 'BLART': 'AB', 'UMSKZ': '', 'ZUONR': '20240914', 'STORE_CODE': '', 'STATE_CODE': '', 'HSN_SAC': '', 'PRCTR': 'HO', 'H_BLDAT': '20240914', 'FAEDT': '20240914', 'LTEXT': 'Accounting document', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240914', 'BELNR': '1004511237', 'SHKZG': 'S', 'XBLNR': '', 'SGTXT': '', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('24304.50'), 'NET_CREDIT': Decimal('0.00'), 'AUGBL': '1004511237', 'AUGDT': '20240914', 'BLART': 'AB', 'UMSKZ': '', 'ZUONR': '20240914', 'STORE_CODE': '', 'STATE_CODE': '', 'HSN_SAC': '', 'PRCTR': 'HO', 'H_BLDAT': '20240914', 'FAEDT': '20240914', 'LTEXT': 'Accounting document', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240919', 'BELNR': '1900164437', 'SHKZG': 'H', 'XBLNR': 'INC-0824-3314', 'SGTXT': "Staff incentives-Aug'24-LP-3314", 'GR_AMOUNT': Decimal('-4385.00'), 'TAX_AMOUNT': Decimal('-220.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('4165.00'), 'AUGBL': '1005526321', 'AUGDT': '20241025', 'BLART': 'KR', 'UMSKZ': '8', 'ZUONR': '3314', 'STORE_CODE': '102123', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240831', 'FAEDT': '20240919', 'LTEXT': 'Vendor invoice - FI', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240919', 'BELNR': '1900164927', 'SHKZG': 'H', 'XBLNR': 'INC-0824-9802', 'SGTXT': "Staff incentives-Aug'24-LP-9802", 'GR_AMOUNT': Decimal('-1388.00'), 'TAX_AMOUNT': Decimal('-70.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('1318.00'), 'AUGBL': '1005510153', 'AUGDT': '20241025', 'BLART': 'KR', 'UMSKZ': '8', 'ZUONR': '9802', 'STORE_CODE': '9000278', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240831', 'FAEDT': '20240919', 'LTEXT': 'Vendor invoice - FI', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240930', 'BELNR': '1900183891', 'SHKZG': 'H', 'XBLNR': 'VC-0924-9802', 'SGTXT': 'VARI COMM-202409-LP-9802', 'GR_AMOUNT': Decimal('-115945.00'), 'TAX_AMOUNT': Decimal('-5798.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('110147.00'), 'AUGBL': '1005185324', 'AUGDT': '20241010', 'BLART': 'KR', 'UMSKZ': '8', 'ZUONR': '9802', 'STORE_CODE': '9000278', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240930', 'FAEDT': '20240930', 'LTEXT': 'Vendor invoice - FI', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240930', 'BELNR': '6501107793', 'SHKZG': 'S', 'XBLNR': 'MSDR242100000956', 'SGTXT': 'CC charges-202409-9802', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('683.22'), 'NET_CREDIT': Decimal('0.00'), 'AUGBL': '2100088922', 'AUGDT': '20241009', 'BLART': 'YV', 'UMSKZ': '', 'ZUONR': 'Q9000278OD', 'STORE_CODE': 'NA', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HO', 'H_BLDAT': '20240930', 'FAEDT': '20240930', 'LTEXT': 'Trnsf btn Cust 2 VeN', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240930', 'BELNR': '6501106222', 'SHKZG': 'S', 'XBLNR': 'MSDR242100000925', 'SGTXT': 'CC charges-202409-3314', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('868.48'), 'NET_CREDIT': Decimal('0.00'), 'AUGBL': '2100088922', 'AUGDT': '20241009', 'BLART': 'YV', 'UMSKZ': '', 'ZUONR': 'Q102123OD', 'STORE_CODE': 'NA', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HO', 'H_BLDAT': '20240930', 'FAEDT': '20240930', 'LTEXT': 'Trnsf btn Cust 2 VeN', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20240930', 'BELNR': '1900182546', 'SHKZG': 'H', 'XBLNR': 'VC-0924-3314', 'SGTXT': 'VARI COMM-202409-LP-3314', 'GR_AMOUNT': Decimal('-82553.00'), 'TAX_AMOUNT': Decimal('-4128.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('78425.00'), 'AUGBL': '1005196528', 'AUGDT': '20241011', 'BLART': 'KR', 'UMSKZ': '8', 'ZUONR': '3314', 'STORE_CODE': '102123', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20240930', 'FAEDT': '20240930', 'LTEXT': 'Vendor invoice - FI', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20241007', 'BELNR': '4600104098', 'SHKZG': 'H', 'XBLNR': 'VC-0924-9802', 'SGTXT': 'VARI COMM-202409-LP-9802', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('131017.00'), 'AUGBL': '2100088922', 'AUGDT': '20241009', 'BLART': 'ZK', 'UMSKZ': '', 'ZUONR': '9802', 'STORE_CODE': '9000278', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'LP', 'H_BLDAT': '20241007', 'FAEDT': '20241007', 'LTEXT': 'Vendor 2 Vendor post', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20241007', 'BELNR': '4600104097', 'SHKZG': 'H', 'XBLNR': 'VC-0924-3314', 'SGTXT': 'VARI COMM-202409-LP-3314', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('93285.00'), 'AUGBL': '2100088922', 'AUGDT': '20241009', 'BLART': 'ZK', 'UMSKZ': '', 'ZUONR': '3314', 'STORE_CODE': '102123', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'LP', 'H_BLDAT': '20241007', 'FAEDT': '20241007', 'LTEXT': 'Vendor 2 Vendor post', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20241008', 'BELNR': '4600106138', 'SHKZG': 'S', 'XBLNR': 'VC-0924-9802', 'SGTXT': 'VARI COMM-202409-LP-9802', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('131017.00'), 'NET_CREDIT': Decimal('0.00'), 'AUGBL': '1005389638', 'AUGDT': '20241020', 'BLART': 'ZK', 'UMSKZ': '', 'ZUONR': '9802', 'STORE_CODE': '9000278', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'LP', 'H_BLDAT': '20241008', 'FAEDT': '20241008', 'LTEXT': 'Vendor 2 Vendor post', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20241008', 'BELNR': '4600106137', 'SHKZG': 'S', 'XBLNR': 'VC-0924-3314', 'SGTXT': 'VARI COMM-202409-LP-3314', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('93285.00'), 'NET_CREDIT': Decimal('0.00'), 'AUGBL': '1005389638', 'AUGDT': '20241020', 'BLART': 'ZK', 'UMSKZ': '', 'ZUONR': '3314', 'STORE_CODE': '102123', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'LP', 'H_BLDAT': '20241008', 'FAEDT': '20241008', 'LTEXT': 'Vendor 2 Vendor post', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20241010', 'BELNR': '1900191475', 'SHKZG': 'H', 'XBLNR': 'JP/ROK/24-25/016', 'SGTXT': 'VARI COMM-202409-LP-9802', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('20870.10'), 'AUGBL': '1005389638', 'AUGDT': '20241020', 'BLART': 'KR', 'UMSKZ': '', 'ZUONR': '9802', 'STORE_CODE': '9000278', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20241004', 'FAEDT': '20241007', 'LTEXT': 'Vendor invoice - FI', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20241010', 'BELNR': '1005185324', 'SHKZG': 'S', 'XBLNR': '', 'SGTXT': '', 'GR_AMOUNT': Decimal('-115945.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('110147.00'), 'NET_CREDIT': Decimal('0.00'), 'AUGBL': '1005185324', 'AUGDT': '20241010', 'BLART': 'AB', 'UMSKZ': '8', 'ZUONR': '20241010', 'STORE_CODE': '', 'STATE_CODE': '', 'HSN_SAC': '', 'PRCTR': 'HO', 'H_BLDAT': '20241010', 'FAEDT': '20241010', 'LTEXT': 'Accounting document', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20241010', 'BELNR': '4600108626', 'SHKZG': 'S', 'XBLNR': 'JP/ROK/24-25/016', 'SGTXT': 'VARI COMM-202409-LP-9802', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('110147.75'), 'NET_CREDIT': Decimal('0.00'), 'AUGBL': '1005185324', 'AUGDT': '20241010', 'BLART': 'ZK', 'UMSKZ': '8', 'ZUONR': '9802', 'STORE_CODE': '9000278', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20241004', 'FAEDT': '20241004', 'LTEXT': 'Vendor 2 Vendor post', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20241010', 'BELNR': '1005185324', 'SHKZG': 'H', 'XBLNR': '', 'SGTXT': '', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('110147.75'), 'AUGBL': '1005185324', 'AUGDT': '20241010', 'BLART': 'AB', 'UMSKZ': '8', 'ZUONR': '20241010', 'STORE_CODE': '', 'STATE_CODE': '', 'HSN_SAC': '', 'PRCTR': 'HO', 'H_BLDAT': '20241010', 'FAEDT': '20241010', 'LTEXT': 'Accounting document', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20241010', 'BELNR': '4600108626', 'SHKZG': 'H', 'XBLNR': 'JP/ROK/24-25/016', 'SGTXT': 'VARI COMM-202409-LP-9802', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('110147.75'), 'AUGBL': '1005389638', 'AUGDT': '20241020', 'BLART': 'ZK', 'UMSKZ': '', 'ZUONR': '9802', 'STORE_CODE': '9000278', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20241004', 'FAEDT': '20241004', 'LTEXT': 'Vendor 2 Vendor post', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20241011', 'BELNR': '1005196528', 'SHKZG': 'H', 'XBLNR': '', 'SGTXT': '', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('78425.35'), 'AUGBL': '1005196528', 'AUGDT': '20241011', 'BLART': 'AB', 'UMSKZ': '8', 'ZUONR': '20241011', 'STORE_CODE': '', 'STATE_CODE': '', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20241011', 'FAEDT': '20241011', 'LTEXT': 'Accounting document', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20241011', 'BELNR': '4600109095', 'SHKZG': 'S', 'XBLNR': 'JP/ROK/24-25/015', 'SGTXT': 'VARI COMM-202409-LP-3314', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('78425.35'), 'NET_CREDIT': Decimal('0.00'), 'AUGBL': '1005196528', 'AUGDT': '20241011', 'BLART': 'ZK', 'UMSKZ': '8', 'ZUONR': '3314', 'STORE_CODE': '102123', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20241004', 'FAEDT': '20241004', 'LTEXT': 'Vendor 2 Vendor post', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20241011', 'BELNR': '1900192669', 'SHKZG': 'H', 'XBLNR': 'JP/ROK/24-25/015', 'SGTXT': 'VARI COMM-202409-LP-3314', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('14859.54'), 'AUGBL': '1005389638', 'AUGDT': '20241020', 'BLART': 'KR', 'UMSKZ': '', 'ZUONR': '3314', 'STORE_CODE': '102123', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20241004', 'FAEDT': '20241007', 'LTEXT': 'Vendor invoice - FI', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20241011', 'BELNR': '1005196528', 'SHKZG': 'S', 'XBLNR': '', 'SGTXT': '', 'GR_AMOUNT': Decimal('-82553.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('78425.00'), 'NET_CREDIT': Decimal('0.00'), 'AUGBL': '1005196528', 'AUGDT': '20241011', 'BLART': 'AB', 'UMSKZ': '8', 'ZUONR': '20241011', 'STORE_CODE': '', 'STATE_CODE': '', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20241011', 'FAEDT': '20241011', 'LTEXT': 'Accounting document', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20241011', 'BELNR': '4600109095', 'SHKZG': 'H', 'XBLNR': 'JP/ROK/24-25/015', 'SGTXT': 'VARI COMM-202409-LP-3314', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('78425.35'), 'AUGBL': '1005389638', 'AUGDT': '20241020', 'BLART': 'ZK', 'UMSKZ': '', 'ZUONR': '3314', 'STORE_CODE': '102123', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20241004', 'FAEDT': '20241004', 'LTEXT': 'Vendor 2 Vendor post', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20241020', 'BELNR': '1005389638', 'SHKZG': 'H', 'XBLNR': '', 'SGTXT': '', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('224302.00'), 'AUGBL': '1005389638', 'AUGDT': '20241020', 'BLART': 'AB', 'UMSKZ': '', 'ZUONR': '20241020', 'STORE_CODE': '', 'STATE_CODE': '', 'HSN_SAC': '', 'PRCTR': 'HO', 'H_BLDAT': '20241020', 'FAEDT': '20241020', 'LTEXT': 'Accounting document', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20241020', 'BELNR': '1005389638', 'SHKZG': 'S', 'XBLNR': '', 'SGTXT': '', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('35729.64'), 'NET_CREDIT': Decimal('0.00'), 'AUGBL': '1005389638', 'AUGDT': '20241020', 'BLART': 'AB', 'UMSKZ': '', 'ZUONR': '20241020', 'STORE_CODE': '', 'STATE_CODE': '', 'HSN_SAC': '', 'PRCTR': 'HO', 'H_BLDAT': '20241020', 'FAEDT': '20241020', 'LTEXT': 'Accounting document', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20241020', 'BELNR': '1005389638', 'SHKZG': 'S', 'XBLNR': '', 'SGTXT': '', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('188573.10'), 'NET_CREDIT': Decimal('0.00'), 'AUGBL': '1005389638', 'AUGDT': '20241020', 'BLART': 'AB', 'UMSKZ': '', 'ZUONR': '20241020', 'STORE_CODE': '', 'STATE_CODE': '', 'HSN_SAC': '', 'PRCTR': 'HO', 'H_BLDAT': '20241020', 'FAEDT': '20241020', 'LTEXT': 'Accounting document', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20241025', 'BELNR': '1900204558', 'SHKZG': 'H', 'XBLNR': 'JP/ROK/24-25/017', 'SGTXT': "Staff incentives-Aug'24-LP-3314", 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('789.30'), 'AUGBL': '2100097928', 'AUGDT': '20241029', 'BLART': 'KR', 'UMSKZ': '', 'ZUONR': '3314', 'STORE_CODE': '102123', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20241004', 'FAEDT': '20241004', 'LTEXT': 'Vendor invoice - FI', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20241025', 'BELNR': '1005510153', 'SHKZG': 'H', 'XBLNR': '', 'SGTXT': '', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('1318.60'), 'AUGBL': '1005510153', 'AUGDT': '20241025', 'BLART': 'AB', 'UMSKZ': '8', 'ZUONR': '20241025', 'STORE_CODE': '', 'STATE_CODE': '', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20241025', 'FAEDT': '20241025', 'LTEXT': 'Accounting document', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20241025', 'BELNR': '1005526321', 'SHKZG': 'H', 'XBLNR': '', 'SGTXT': '', 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('4165.75'), 'AUGBL': '1005526321', 'AUGDT': '20241025', 'BLART': 'AB', 'UMSKZ': '8', 'ZUONR': '20241025', 'STORE_CODE': '', 'STATE_CODE': '', 'HSN_SAC': '', 'PRCTR': 'HO', 'H_BLDAT': '20241025', 'FAEDT': '20241025', 'LTEXT': 'Accounting document', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20241025', 'BELNR': '4600115338', 'SHKZG': 'H', 'XBLNR': 'JP/ROK/24-25/017', 'SGTXT': "Staff incentives-Aug'24-LP-3314", 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('4165.75'), 'AUGBL': '2100097927', 'AUGDT': '20241029', 'BLART': 'ZK', 'UMSKZ': '', 'ZUONR': '3314', 'STORE_CODE': '102123', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20241004', 'FAEDT': '20241004', 'LTEXT': 'Vendor 2 Vendor post', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20241025', 'BELNR': '1900204434', 'SHKZG': 'H', 'XBLNR': 'JP/ROK/24-25/018', 'SGTXT': "Staff incentives-Aug'24-LP-9802", 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('249.84'), 'AUGBL': '2100097928', 'AUGDT': '20241029', 'BLART': 'KR', 'UMSKZ': '', 'ZUONR': '9802', 'STORE_CODE': '9000278', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20241004', 'FAEDT': '20241004', 'LTEXT': 'Vendor invoice - FI', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20241025', 'BELNR': '1005510153', 'SHKZG': 'S', 'XBLNR': '', 'SGTXT': '', 'GR_AMOUNT': Decimal('-1388.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('1318.00'), 'NET_CREDIT': Decimal('0.00'), 'AUGBL': '1005510153', 'AUGDT': '20241025', 'BLART': 'AB', 'UMSKZ': '8', 'ZUONR': '20241025', 'STORE_CODE': '', 'STATE_CODE': '', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20241025', 'FAEDT': '20241025', 'LTEXT': 'Accounting document', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20241025', 'BELNR': '4600115338', 'SHKZG': 'S', 'XBLNR': 'JP/ROK/24-25/017', 'SGTXT': "Staff incentives-Aug'24-LP-3314", 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('4165.75'), 'NET_CREDIT': Decimal('0.00'), 'AUGBL': '1005526321', 'AUGDT': '20241025', 'BLART': 'ZK', 'UMSKZ': '8', 'ZUONR': '3314', 'STORE_CODE': '102123', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20241004', 'FAEDT': '20241004', 'LTEXT': 'Vendor 2 Vendor post', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20241025', 'BELNR': '4600115322', 'SHKZG': 'S', 'XBLNR': 'JP/ROK/24-25/018', 'SGTXT': "Staff incentives-Aug'24-LP-9802", 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('1318.60'), 'NET_CREDIT': Decimal('0.00'), 'AUGBL': '1005510153', 'AUGDT': '20241025', 'BLART': 'ZK', 'UMSKZ': '8', 'ZUONR': '9802', 'STORE_CODE': '9000278', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20241004', 'FAEDT': '20241004', 'LTEXT': 'Vendor 2 Vendor post', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20241025', 'BELNR': '1005526321', 'SHKZG': 'S', 'XBLNR': '', 'SGTXT': '', 'GR_AMOUNT': Decimal('-4385.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('4165.00'), 'NET_CREDIT': Decimal('0.00'), 'AUGBL': '1005526321', 'AUGDT': '20241025', 'BLART': 'AB', 'UMSKZ': '8', 'ZUONR': '20241025', 'STORE_CODE': '', 'STATE_CODE': '', 'HSN_SAC': '', 'PRCTR': 'HO', 'H_BLDAT': '20241025', 'FAEDT': '20241025', 'LTEXT': 'Accounting document', 'KIDNO': ''}, {'GJAHR': '2024', 'BUDAT': '20241025', 'BELNR': '4600115322', 'SHKZG': 'H', 'XBLNR': 'JP/ROK/24-25/018', 'SGTXT': "Staff incentives-Aug'24-LP-9802", 'GR_AMOUNT': Decimal('0.00'), 'TAX_AMOUNT': Decimal('0.00'), 'NET_DEBIT': Decimal('0.00'), 'NET_CREDIT': Decimal('1318.60'), 'AUGBL': '2100097927', 'AUGDT': '20241029', 'BLART': 'ZK', 'UMSKZ': '', 'ZUONR': '9802', 'STORE_CODE': '9000278', 'STATE_CODE': '21', 'HSN_SAC': '', 'PRCTR': 'HLP_COMM', 'H_BLDAT': '20241004', 'FAEDT': '20241004', 'LTEXT': 'Vendor 2 Vendor post', 'KIDNO': ''}]}, use_decimal=True)

        data = json.loads(json_data) # parsing JSON DATA to python dict to manipulate it / filter it

        if ledgerType == "gst":
            data['INT_LEDGER'] = [
                row for row in data.get('INT_LEDGER', [])
                if str(row.get('BELNR', '')).startswith('19') or str(row.get('BELNR', '')).startswith('16')
            ]

        return Response({
            "code": 201,
            "status": "Success",
            "ledger_details":data
        }, status=200)
        
        
    except Exception as e:
        return Response({"code": 500, "status": "Error", "message": "Error connecting to SAP:", "error": str(e)}, status=500)

    # finally:
    #     if conn:
    #         conn.close() 
 
 
@api_view(["POST"])
@permission_classes([AllowAny])
def commission_detail(request):
    commission_type = request.data.get("commissionType")
    store_code = request.data.get("storeCode")
    from_date = request.data.get("fromDate")
    to_date = request.data.get("toDate")

    print(from_date)
    print(to_date)
    if not commission_type or not store_code or not from_date or not to_date:
        return Response(
            {
                "code": 400, 
                "status": "Failure", 
                "message": "Missing Field"
            }, status=400)

    try:
        commission_map = { 'Variable': 'V', 'Boss': 'B', 'Fixed and MG': 'E' }    
        commission_code = commission_map.get(commission_type.lower(), 'V')
        placeholders = ','.join('?' for _ in store_code)
        query = f"""SELECT * FROM CommissionTable
                    WHERE Sap_Store_Code IN ({placeholders})
                    AND Commission_Type = ?
                    AND (
                        CAST(Year AS VARCHAR) + RIGHT('0' + CAST(Month AS VARCHAR), 2)
                        BETWEEN ? AND ?
                    )""" 
        params = ( store_code + [commission_code, from_date, to_date] )  

        # Connect to MSSQL
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute(query, params)
        rows = cursor.fetchall()  
        columns = [col[0] for col in cursor.description]
        data = [dict(zip(columns, row)) for row in rows]
        print(data)
        return Response(
            {
                "code": 201, 
                "status": "Success", 
                "data": data
             }, status=201)  
       
    except Exception as e:
        return Response(
            {
                "code": 500, 
                "status": "Error", 
                "message": "Error connecting to SAP", 
                "error": str(e)
            }, status=500)
 
    # finally:
    #     if conn:
    #         conn.close() 


def generate_pdf_bytes(data):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)
    
    # Set colors
    navy_blue = (31, 73, 125)
    light_gray = (240, 240, 240)
    total_table_width = sum([40, 20, 25, 30, 20, 20, 20, 20])
    x_start = 10 
    x_content_right = (x_start-5) + total_table_width
    y_start = pdf.get_y()
    main_section_y_start = pdf.get_y()
    #placing logo
    logo_path = os.path.join(settings.BASE_DIR, 'backend', 'static', 'images', 'logo.jpg')
    logo_width = 35
    logo_height = 25
    logo_x = (pdf.w - logo_width) / 2
    # pdf.set_y(y_start + 5)
    pdf.image(logo_path, x=logo_x, y=pdf.get_y(), w=logo_width, h=logo_height)
    
    #line seperator
    logo_bottom_y = pdf.get_y() + logo_height
    pdf.set_y(logo_bottom_y)
    right_margin = 0
    x_end = pdf.w - right_margin
    pdf.set_draw_color(0, 0, 0)
    pdf.line(x_start, logo_bottom_y, x_start + total_table_width, logo_bottom_y)
    
    #heading
    if data['XBLNR'].startswith("CREDIT NOTE"):
        text = "CREDIT NOTE"
    elif data['XBLNR'] == 'SALARY DEBIT' or  data['XBLNR'] == 'OTH-DEBIT':    
        text = "SERVICE INVOICE"
    ZBAPIFRANCHISE_ST = json.dumps({'RETURN': {'TYPE': '', 'ID': '', 'NUMBER': '000', 'MESSAGE': '', 'LOG_NO': '', 'LOG_MSG_NO': '000000', 'MESSAGE_V1': '', 'MESSAGE_V2': '', 'MESSAGE_V3': '', 'MESSAGE_V4': '', 'PARAMETER': '', 'ROW': 0, 'FIELD': '', 'SYSTEM': ''}, 'WA_FRNCHSE': {'NAME1': 'JOHAR PERIPHERALS', 'J_1IPANNO': 'ADAPJ4450A', 'HOUSE_NUM1': '1', 'STREET': 'PROP  CHETAN JOHAR', 'CITY1': 'RANCHI', 'POST_CODE1': '834002', 'LANDX': 'India', 'TEL_NUMBER': '06512412778', 'SMTP_ADDR': 'aeplranchi@yahoo.com', 'SERVICETAX': '', 'BANKN': '31755137083', 'BANKA': 'State Bank Of India', 'REGIO': '20', 'BEZEI': 'Jharkhand', 'IFSC': 'SBIN0007957', 'STCD3': '20ADAPJ4450A2ZJ'}})
    ZBAPIFRANCHISE_ST_data = json.loads(ZBAPIFRANCHISE_ST)
    query = f"""SELECT StateName AS STATE, GSTN, StateAddress AS ADDRESS FROM StateAddresses WHERE StateCode= ?"""
    # Connect to MSSQL
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(query, [data['BUPLA']])
    rows = cursor.fetchall()
    columns = [col[0] for col in cursor.description]
    state_data = [dict(zip(columns, row)) for row in rows]
    # pdf.set_y(logo_bottom_y + 5)
    pdf.set_font('Arial', 'B', 10)
    text_width = pdf.get_string_width(text)
    x_center = (pdf.w - text_width) / 2
    pdf.set_x(x_center)
    pdf.cell(text_width, 10, text, ln=True, align='C')
    
    #line seperator
    separator_y = pdf.get_y()
    # pdf.set_y(separator_y)
    
    pdf.set_draw_color(0, 0, 0)
    pdf.line(x_start, separator_y, x_start + total_table_width, separator_y)
    
    #company info
    # pdf.set_y(separator_y + 5)
    pdf.set_font('Arial', '', 10)
    content_1 = "ADITYA BIRLA LIFESTYLE BRANDS LIMITED"
    content_2 = state_data[0]['ADDRESS']
    
    content_1_width = pdf.get_string_width(content_1)
    x_center_1 = (pdf.w - content_1_width) / 2  # Center horizontally
    pdf.set_x(x_center_1)
    pdf.cell(content_1_width, 6, content_1, ln=1, align='C')

    # Center the second line of content
    content_2_width = pdf.get_string_width(content_2)
    x_center_2 = (pdf.w - content_2_width) / 2  # Center horizontally
    pdf.set_x(x_center_2)
    pdf.cell(content_2_width, 6, content_2, ln=1, align='C')
    
    # Add "state" and "Orissa" on the left side, and "state_code" and "00021" on the right side
    line_after_content_y = pdf.get_y()
    # pdf.set_y(line_after_content_y + 5) 
    pdf.set_font('Arial', '', 10)
    left_text = "state: " + state_data[0]['STATE']
    right_text = "state_code: " + data['BUPLA']
    left_text_width = pdf.get_string_width(left_text)
    right_text_width = pdf.get_string_width(right_text)
    pdf.set_x(x_start)
    pdf.cell(left_text_width, 6, left_text, ln=0)

    x_right = x_content_right - right_text_width
    pdf.set_x(x_right)
    pdf.cell(right_text_width, 6, right_text, ln=1)
    left_text = "GSTN of Service Provider:: " + state_data[0]['GSTN']
    right_text = "PAN NO: AAECP2371C"
    left_text_width = pdf.get_string_width(left_text)
    right_text_width = pdf.get_string_width(right_text)
    pdf.set_x(x_start)
    pdf.cell(left_text_width, 6, left_text, ln=0)

    x_right = x_content_right - right_text_width
    pdf.set_x(x_right)
    pdf.cell(right_text_width, 6, right_text, ln=1)
    
    #line seperator
    line_after_content_y = pdf.get_y()
    # pdf.set_y(line_after_content_y)
    pdf.set_draw_color(0, 0, 0) 
    pdf.line(x_start, line_after_content_y, x_start + total_table_width, line_after_content_y)
    
    
    #add invoice content
    line_after_content_y = pdf.get_y()
    # pdf.set_y(line_after_content_y + 5) 
    pdf.set_font('Arial', '', 10)
    left_text = "Invoice No.: " + data['Invoice']
    right_text = "Date: " + data['BUDAT']
    left_text_width = pdf.get_string_width(left_text)
    right_text_width = pdf.get_string_width(right_text)
    pdf.set_x(x_start)
    pdf.cell(left_text_width, 6, left_text, ln=0)

    x_right = x_content_right - right_text_width
    pdf.set_x(x_right)
    pdf.cell(right_text_width, 6, right_text, ln=1)
    left_text = "Details of Service Receiver (Billed To) -:"
    right_text = ""
    left_text_width = pdf.get_string_width(left_text)
    right_text_width = pdf.get_string_width(right_text)
    pdf.set_x(x_start)
    pdf.cell(left_text_width, 6, left_text, ln=0)

    x_right = x_content_right - right_text_width
    pdf.set_x(x_right)
    pdf.cell(right_text_width, 6, right_text, ln=1)

    
    #line seperator
    line_after_content_y = pdf.get_y()
    # pdf.set_y(line_after_content_y)
    pdf.set_draw_color(0, 0, 0) 
    pdf.line(x_start, line_after_content_y, x_start + total_table_width, line_after_content_y)
    
    #Vendor info
    # pdf.set_y(line_after_content_y + 5) 
    pdf.set_font('Arial', '', 10)
    label_width = 40
    value_width = 0
    vendor_info = [
    ("Vendor Code:", data['VENDOR']),
    ("Vendor Name:", ZBAPIFRANCHISE_ST_data['WA_FRNCHSE']['NAME1']),
    ("Address:", ZBAPIFRANCHISE_ST_data['WA_FRNCHSE']['HOUSE_NUM1'] + ZBAPIFRANCHISE_ST_data['WA_FRNCHSE']['STREET'] + ZBAPIFRANCHISE_ST_data['WA_FRNCHSE']['CITY1']),
    ("", state_data[0]['STATE']),
    ("", ZBAPIFRANCHISE_ST_data['WA_FRNCHSE']['POST_CODE1']),
    ("", ZBAPIFRANCHISE_ST_data['WA_FRNCHSE']['LANDX']),
    ("State:", state_data[0]['STATE']),
    ("GST No.:", data['STCD3']),
    ("Store Code:", data['STORECODE']),
    ("Text:", data['Text']),
    ("Document No.:", data['BELNR']),
]
    for label, value in vendor_info:
        pdf.set_x(x_start)
        if label:  # Print label if not empty
           pdf.set_font('Arial', 'B', 12)
           pdf.cell(label_width, 6, label, ln=0)
        else:  # Empty label = indentation
           pdf.cell(label_width, 6, "", ln=0)
        pdf.set_font('Arial', '', 12)
        pdf.cell(value_width, 6, value, ln=1)
    
    # pdf.set_y(pdf.get_y() + 10)
    pdf.set_font('Arial', 'B', 10)
    columns = [
    ("Description", 40),
    ("Month", 20),
    ("HSN/SAC Code", 25),
    ("Taxable Amount", 30),
    ("CGST", 40),         # This will split into Rate (20) + Amt (20)
    ("SGST/UGST", 40),    # This will split into Rate (20) + Amt (20)
]
    pdf.set_fill_color(31, 73, 125)
    pdf.set_text_color(255, 255, 255)
    x_start = 10
    y_start = pdf.get_y()
    row_height_main = 8
    row_height_sub = 8
    x = x_start
    
    for label, width in columns:
       if label in ["CGST", "SGST/UGST"]:
        # pdf.rect(x, y_start, width, row_height_main)
        pdf.set_xy(x, y_start)
        pdf.cell(width, row_height_main, label, border=1, align='C', fill=True)
        x += width
       else:
        # pdf.rect(x, y_start, width, row_height_main + row_height_sub)  # Span 2 rows
        pdf.set_xy(x, y_start)  # Center vertically
        pdf.cell(width, row_height_main + row_height_sub, label, border=1, align='C', fill=True)
        x += width
    
        

    # Second row: Sub headers under CGST and SGST/UGST
    x = x_start + 40 + 20 + 25 + 30  # Skip Description, Month, HSN/SAC Code, Taxable Amount
    y_sub = y_start + row_height_main
    sub_headers = ["Rate", "Amt", "Rate", "Amt"]
    sub_width = 20

    for sub in sub_headers:
       pdf.rect(x, y_sub, sub_width, row_height_sub)
       pdf.set_xy(x, y_sub)
       pdf.cell(sub_width, row_height_sub, sub, border=1, align='C', fill=True)
       x += sub_width

    # Move Y position to start data rows
    pdf.set_y(y_sub + row_height_sub)

    # Reset font for data
    pdf.set_font('Arial', '', 10)

    # Example data row
    gst_query = f"""SELECT EMPNAME, EMPLOY, HSN_SAC, CAST(AMOUNT AS varchar) AS AMOUNT, CAST(CGST AS varchar) AS CGST, CAST((AMOUNT*CGST)/100 AS varchar) AS CGSTAmt, CAST(SGST AS varchar) AS SGST, CAST((AMOUNT*SGST)/100 AS varchar) AS SGSTAmt FROM ServiceInvoiceMain WHERE BELNR= ? AND CALMNTH= ?"""
    cursor.execute(gst_query, [data['BELNR'],data['CALMNTH']])
    data_rows = cursor.fetchall()
    #data_rows = [("Manpower Services", "Apr", "998514", "15,000.00", "9%", "1,350.00", "9%", "1,350.00"),# Add more rows as needed]
    pdf.set_text_color(0, 0, 0)
    pdf.set_fill_color(255, 255, 255)

    for row in data_rows:
        x = x_start
        y = pdf.get_y()
        widths = [40, 20, 25, 30, 20, 20, 20, 20]

        for i, val in enumerate(row):
            w = widths[i]
            pdf.rect(x, y, w, row_height_main)
            pdf.set_xy(x, y)
            pdf.cell(w, row_height_main, val, align='C')
            x += w
        pdf.set_y(y + row_height_main)
    # Draw total row
    pdf.set_fill_color(31, 73, 125)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font('Arial', 'B', 10)
    x = x_start
    y = pdf.get_y()
    row_height_total_header = 8
    TAmount = '0'
    CAmount = '0'
    SAmount = '0'
    for row in data_rows:
        for i, val in enumerate(row):
            if i == 3 :
                TAmount = val
            if i == 5 :
                CAmount = val
            if i == 7 :
                SAmount = val
    total_row1 = ["Total", "", "", TAmount, "", CAmount, "", SAmount]
    total_widths = [40, 20, 25, 30, 20, 20, 20, 20]
    for i, value in enumerate(total_row1):
        w = total_widths[i]
        pdf.rect(x, y, w, row_height_total_header)
        pdf.set_xy(x, y)
        pdf.cell(w, row_height_total_header, value, align='C', fill=True)
        x += w
    pdf.set_y(y + row_height_total_header)
    pdf.set_x(x_start)
    pdf.set_text_color(0, 0, 0)
    pdf.set_fill_color(255, 255, 255)
    col1_width = total_table_width * 0.65  # Adjust proportion if needed
    col2_width = total_table_width - col1_width
    FTAmount = float(total_row1[3])
    FCAmount = float(total_row1[5])
    FSAmount = float(total_row1[7])
    CSGST = FCAmount + FSAmount
    final_total = FTAmount + CSGST
    pdf.cell(col1_width, 8, num2words(final_total) + ' only', border=1, align='L')
    pdf.cell(col2_width, 8, "Total Invoice value: " + str(final_total), border=1, align='R')

    # Final table border (box around full table area)
    y_end = pdf.get_y()
    pdf.set_draw_color(0, 0, 0)
    pdf.rect(x_start, y_start, sum(total_widths), y_end - y_start)
    main_section_y_end = pdf.get_y()
    pdf.set_draw_color(0, 0, 0)
    pdf.rect(x_start, main_section_y_start, sum([40, 20, 25, 30, 20, 20, 20, 20]), main_section_y_end - main_section_y_start)


    # Footer note
    footer_margin = 10
    pdf.set_y(pdf.get_y() + footer_margin)
    footer_text = "[This is a system generated stationery and needs no signature]"
    pdf.set_font("Arial", "I", 9)
    pdf.set_text_color(100)
    pdf.cell(0, 5, footer_text, ln=1, align="C")
    
    return pdf.output(dest='S')


@api_view(["POST"])
@permission_classes([AllowAny])
def credit_debit(request):
    store_code = request.data.get("storeCode")
    year = request.data.get("year")
    month = request.data.get("month")
    
    if not store_code or not year or not month:
        return Response({"code": 400, "status": "Failure", "message": "StoreUID is required"}, status=400)

    try:
        calmnth = f"{year}{month.zfill(2)}"
        print(calmnth)
        if (int(year) == 2017 and int(month) >= 7) or int(year) > 2017:
            print("firstone")
            query = """
            SELECT BELNR, BELNR + ' ' + MIN([TEXT]) AS Document, MIN(INVOICE_NUM) AS Invoice, 
                   MIN(BUPLA) AS BUPLA, MIN(STCD3) AS STCD3, CAST(MIN(CALMNTH) AS VARCHAR(6)) AS CALMNTH, 
                   MIN([TEXT]) AS [Text], MIN(GST_PART) AS GST_PART, MIN(BUDAT) AS BUDAT, XBLNR, 
                   MIN(VENDOR) AS VENDOR,
                   MIN(CGST) AS CGST,
                   MIN(SGST) AS SGST,
                   MIN(BELNR) AS BELNR,
                   MIN(EMPNAME) AS EMPNAME,
                   MIN(EMPLOY) AS EMPLOY,
                   MIN(HSN_SAC) AS HSN_SAC,
                   MIN(DATE1) AS DATE1,
                   MIN(STORECODE) AS STORECODE, 
                   MIN(AMOUNT) AS AMOUNT, 
                   CASE 
                       WHEN XBLNR = 'SALARY DEBIT' THEN 'Salary Debit' 
                       WHEN XBLNR = 'OTH-DEBIT' THEN 'Other Debit' 
                       WHEN XBLNR = 'CREDIT NOTE-SAL' THEN 'Credit Note-Salary' 
                       WHEN XBLNR = 'CREDIT NOTE-OTH' THEN 'Credit Note-Other' 
                   END AS DocType 
            FROM ServiceInvoiceMain 
            WHERE STORECODE = ? AND CALMNTH = ? 
            GROUP BY BELNR, XBLNR
        """
        else:
            print("second")
            query = """
            SELECT BELNR, BELNR + ' ' + MIN([TEXT]) AS Document, MIN(INVOICE_NUM) AS Invoice, 
                   '' AS BUPLA, '' AS STCD3, CAST(MIN(CALMNTH) AS VARCHAR(6)) AS CALMNTH, 
                   MIN([TEXT]) AS [Text], '' AS GST_PART, MIN(BUDAT) AS BUDAT, XBLNR, 
                   MIN(VENDOR) AS VENDOR, 
                   MIN(CGST) AS CGST,
                   MIN(SGST) AS SGST,
                   MIN(BELNR) AS BELNR,
                   MIN(EMPNAME) AS EMPNAME,
                   MIN(EMPLOY) AS EMPLOY,
                   MIN(HSN_SAC) AS HSN_SAC,
                   MIN(DATE1) AS DATE1,
                   MIN(STORECODE) AS STORECODE,
                   MIN(AMOUNT) AS AMOUNT,
                   CASE 
                       WHEN XBLNR = 'SALARY DEBIT' THEN 'Salary Debit' 
                       WHEN XBLNR = 'OTH-DEBIT' THEN 'Other Debit' 
                       WHEN XBLNR = 'CREDIT NOTE-SAL' THEN 'Credit Note-Salary' 
                       WHEN XBLNR = 'CREDIT NOTE-OTH' THEN 'Credit Note-Other' 
                   END AS DocType 
            FROM ServiceInvoiceMain 
            WHERE STORECODE = ? AND CALMNTH = ? 
            GROUP BY BELNR, XBLNR
        """
          
        # Connect to MSSQL
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute(query, [store_code, calmnth])
        rows = cursor.fetchall()  
        columns = [col[0] for col in cursor.description]
        data = [dict(zip(columns, row)) for row in rows]
        compiled_data = []
        for obj in data:
            pdf_bytes = generate_pdf_bytes(obj)
            encoded_pdf = base64.b64encode(pdf_bytes).decode('utf-8')
            compiled_data.append({
                "vendorCode": obj["VENDOR"],
                "type": obj["DocType"],
                "fileData": encoded_pdf,
                "fileName": obj["Document"],
                "downloadName": obj["BELNR"]
                })
        return Response({"code": 201, "status": "Success", "data": compiled_data})  
       
    except Exception as e:
        return Response({"code": 500, "status": "Error", "message": "Error connecting to SAP:", "error": str(e)}, status=500)

    # finally:
    #     if conn:
    #         conn.close() 

@api_view(["POST"])
@permission_classes([AllowAny])
def get_all_tds_details(request):
    panno = request.data.get("PANNO")
    year = request.data.get("year")

    if not panno or not year:
        return Response({"code": 400, "status": "Failure", "message": "PANNO and year are required"}, status=400)

    try:
        directory_path = r"C:\MG_Portal\App_Data\TDSCertificates"
        # ✅ Check if directory exists
        if not os.path.exists(directory_path):
            return Response({
                "code": 404,
                "status": "Failure",
                "message": f"Directory not found: {directory_path}"
            }, status=404)
        
        all_files = os.listdir(directory_path)
        matched_files = []

        for file in all_files:
            if file.endswith(".pdf"):
                file_parts = file.replace(".pdf", "").split("_")
                if len(file_parts) == 3:
                    file_panno, _, file_year = file_parts
                    file_year_part = file_year.split("-")[0]
                    if file_panno == panno and file_year_part == year:
                        matched_files.append(file)

        if not matched_files:
            return Response({
                "code": 204,
                "status": "Success",
                "message": "No files found",
                "files": []
            })

        return Response({
            "code": 200,
            "status": "Success",
            "message": f"Found {len(matched_files)} files",
            "files": matched_files
        })

    except Exception as e:
        return Response({
            "code": 500,
            "status": "Error",
            "message": "Error reading files",
            "error": str(e)
        }, status=500)
    
    # ============================================================


#==============( Details Fetching )========================

# @api_view(["POST"])
# @permission_classes([AllowAny])
# def get_cmr_details(request):
#     storecode = request.data.get("storecode")
#     quarter = request.data.get("quarter")
#     year = request.data.get("year")

#     if not storecode or not quarter or not year:
#         return Response({
#             "code": 400,
#             "status": "Failure",
#             "message": "storecode, quarter, and year are required"
#         }, status=400)

#     try:
        
#         directory_path = r"C:\MG_Portal\App_Data\Documents"
#         all_files = os.listdir(directory_path)
        
#         matched_files = []

#         for file in all_files:
#             if file.endswith(".pdf"):
#                 file_parts = file.replace(".pdf", "").split("-")
#                 if len(file_parts) == 5:
#                     file_store, file_year1, file_year2, file_quarter, file_cmr = file_parts
#                     file_year_part = file_year1 + '-' + file_year2
#                     print(file_store, file_quarter, file_year_part)
#                     print(storecode, quarter, year)

#                     if file_store == storecode and file_quarter == quarter and file_year_part == year:
#                         print("add")
#                         matched_files.append(file)

#         if not matched_files:
#             return Response({
#                 "code": 204,
#                 "status": "Success",
#                 "message": "No files found for the given storecode, quarter, and year",
#                 "files": []
#             })

#         return Response({
#             "code": 200,
#             "status": "Success",
#             "message": f"Found {len(matched_files)} file(s)",
#             "files": matched_files
#         })

#     except Exception as e:
#         return Response({
#             "code": 500,
#             "status": "Error",
#             "message": "Error while processing files",
#             "error": str(e)
#         }, status=500)
    

@api_view(["POST"])
@permission_classes([AllowAny])
def get_cmr_details(request):
    storecode = request.data.get("storecode","")[-4:]
    quarter = request.data.get("quarter")  # Optional
    year = request.data.get("year")        # Optional

    # storecode is mandatory
    if not storecode:
        return Response({
            "code": 400,
            "status": "Failure",
            "message": "storecode is required"
        }, status=400)

    try:
        directory_path = r"C:\MG_Portal\App_Data\Documents"
        all_files = os.listdir(directory_path)

        matched_files = []

        for file in all_files:
            if file.endswith(".pdf"):
                file_parts = file.replace(".pdf", "").split("-")
                if len(file_parts) >= 5:
                    file_store = file_parts[0]
                    file_year1 = file_parts[1]
                    file_year2 = file_parts[2]
                    file_quarter = file_parts[3]
                    file_year_combined = f"{file_year1}-{file_year2}"

                    # Must match storecode
                    if file_store != storecode:
                        continue

                    # Optional filters
                    if quarter and file_quarter != quarter:
                        continue

                    if year and file_year_combined != year:
                        continue

                    matched_files.append(file)

        if not matched_files:
            return Response({
                "code": 204,
                "status": "Success",
                "message": "No files found for the given parameters",
                "files": []
            })

        return Response({
            "code": 200,
            "status": "Success",
            "message": f"Found {len(matched_files)} file(s)",
            "files": matched_files
        })

    except Exception as e:
        return Response({
            "code": 500,
            "status": "Error",
            "message": "Error while processing files",
            "error": str(e)
        }, status=500)



@api_view(["POST"])
@permission_classes([AllowAny])
def upload_cmr_ndc_file(request):
    file = request.FILES.get("file")
    storecode = request.data.get("storecode","")[-4:]
    year = request.data.get("year")
    quarter = request.data.get("quarter")

    if not file or not storecode or not year or not quarter:
        return Response({
            "code": 400,
            "status": "Failure",
            "message": "file, storecode, year, and quarter are required"
        }, status=400)

    try:
        # file extension like .pdf or .xlsx
        ext = os.path.splitext(file.name)[1]

        # new file name
        new_filename = f"{storecode}-{year}-{quarter}-CMR NDC{ext}"

        #  upload path
        destination_path = r"C:\MG_Portal\App_Data\Documents"
        os.makedirs(destination_path, exist_ok=True)

        # path to the file
        full_path = os.path.join(destination_path, new_filename)

        # Save OR overwrite the file if exists 
        with open(full_path, 'wb+') as destination:
            for chunk in file.chunks():
                destination.write(chunk)

        return Response({
            "code": 200,
            "status": "Success",
            "message": "File uploaded successfully",
            "file_name": new_filename
        })

    except Exception as e:
        return Response({
            "code": 500,
            "status": "Error",
            "message": "File upload failed",
            "error": str(e)
        }, status=500)


#
# @api_view(['GET'])
# @permission_classes([AllowAny])
# def get_vendor_with_franchisee(request):
#     try:
#         conn = get_db_connection()
#         with conn.cursor() as cursor:
#             query = """
#                 SELECT 
#                     v.vendorUID,
#                     v.vendorCode,
#                     f.franchiseeName
#                 FROM 
#                     tbl_mVendor v
#                 INNER JOIN 
#                     tbl_xFranchiseeVendor xfv ON v.vendorUID = xfv.vendorUID
#                 INNER JOIN 
#                     tbl_mFranchisee f ON f.franchiseeUID = xfv.franchiseeUID
#                 WHERE 
#                     xfv.isActive = 1
#             """
#             cursor.execute(query)
#             rows = cursor.fetchall()
#             columns = [col[0] for col in cursor.description]
#             data = [dict(zip(columns, row)) for row in rows]

#         return Response({
#             "code": 200,
#             "status": "Success",
#             "data": data
#         })

#     except Exception as e:
#         return Response({
#             "code": 500,
#             "status": "Error",
#             "message": "Internal server error.",
#             "error": str(e)
#         }, status=500)
    

@api_view(['POST'])
@permission_classes([AllowAny])
def get_vendor_with_franchisee(request):
    try:
        vendor_codes = request.data.get("vendorCodes", [])  #  vendor codes

        if not vendor_codes:
            return Response({
                "code": 400,
                "status": "Error",
                "message": "Vendor codes are required."
            }, status=400)

        placeholders = ','.join(['?'] * len(vendor_codes))
        query = f"""
            SELECT 
                v.vendorUID,
                v.vendorCode,
                v.vendorName
            FROM 
                tbl_mVendor v
            INNER JOIN 
                tbl_xFranchiseeVendor xfv ON v.vendorUID = xfv.vendorUID
            INNER JOIN 
                tbl_mFranchisee f ON f.franchiseeUID = xfv.franchiseeUID
            WHERE 
                xfv.isActive = 1
                AND v.vendorCode IN ({placeholders})
        """
        
        # Establish connection and run query
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute(query, tuple(vendor_codes))
            cursor.execute(query, vendor_codes)
            rows = cursor.fetchall()
            columns = [col[0] for col in cursor.description]
            data = [dict(zip(columns, row)) for row in rows]

        return Response({
            "code": 200,
            "status": "Success",
            "data": data
        })

    except Exception as e:
        return Response({
            "code": 500,
            "status": "Error",
            "message": "Internal server error.",
            "error": str(e)
        }, status=500)
    
    #================= ( Knowledge Center file Upload ) =============================

@api_view(["POST"])
@permission_classes([AllowAny])
def upload_knowledge_center_file(request):
    try:
        file = request.FILES.get('file')
        filename = request.POST.get('filename')
        file_type = request.POST.get('selectedFileType')
        description = request.POST.get('fileDescription')
        tags_json = request.POST.get('fileTags')  # Expects JSON string
        category = request.POST.get('category')

        if not file or not category:
            return Response({
                "code": 400,
                "status": "Failure",
                "message": "File and category are required"
            }, status=400)

        # Parse tags JSON
        try:
            tags_list = json.loads(tags_json) if tags_json else []
            tags_str = ','.join([tag.strip() for tag in tags_list])
        except Exception as parse_err:
            return Response({
                "code": 400,
                "status": "Failure",
                "message": "Invalid tags format. Should be a JSON string list."
            }, status=400)

        # Construct dynamic directory based on category
        base_path = r"C:\MG_Portal\App_Data\knowledge_center"
        directory_path = os.path.join(base_path, category)

        if not os.path.exists(directory_path):
            os.makedirs(directory_path)

        file_path = os.path.join(directory_path, filename)

        # Save the uploaded file to disk
        with open(file_path, 'wb+') as destination:
            for chunk in file.chunks():
                destination.write(chunk)

        # Insert into DB
        conn = get_db_connection()
        cursor = conn.cursor()
        insert_query = """
            INSERT INTO knowledge_center 
            (file_name, file_path, file_type, description, category, tags)
            VALUES (?, ?, ?, ?, ?, ?)
        """
        cursor.execute(insert_query, filename, file_path, file_type, description, category, tags_str)
        conn.commit()
        cursor.close()
        conn.close()

        return Response({
            "code": 200,
            "status": "Success",
            "message": "File uploaded successfully"
        })

    except Exception as e:
        return Response({
            "code": 500,
            "status": "Error",
            "message": "Internal server error",
            "error": str(e)
        }, status=500)

@api_view(['GET'])
@permission_classes([AllowAny])
def get_knowledge_center_files(request):
    category = request.GET.get('category', None)

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        if category:
            cursor.execute("""
                SELECT id, file_name, file_path, file_type, description, category, tags
                FROM dbo.knowledge_center
                WHERE category = ?
                ORDER BY id DESC
            """, (category,))
        else:
            cursor.execute("""
                SELECT id, file_name, file_path, file_type, description, category, tags
                FROM dbo.knowledge_center
                ORDER BY id DESC
            """)

        rows = cursor.fetchall()
        cursor.close()
        conn.close()

        columns = ['id', 'file_name', 'file_path', 'file_type', 'description', 'category', 'tags']

        data = [dict(zip(columns, row)) for row in rows]

        return Response({
            "code": 200,
            "status": "Success",
            "data": data
        })

    except Exception as e:
        return Response({
            "code": 500,
            "status": "Error",
            "message": str(e)
        }, status=500)

# views.py
@api_view(['DELETE'])
@permission_classes([AllowAny])
def delete_knowledge_center_file(request, file_id):
    try:
        if not file_id:
            return Response({
                "code": 400,
                "status": "Error",
                "message": "'file_id' is required."
            }, status=400)

        conn = get_db_connection()
        with conn.cursor() as cursor:
            delete_query = """DELETE FROM knowledge_center WHERE id = ?"""
            cursor.execute(delete_query, (file_id,))
            affected = cursor.rowcount
            conn.commit()

        if affected == 0:
            return Response({
                "code": 404,
                "status": "Error",
                "message": f"No file found with id {file_id}."
            }, status=404)

        return Response({
            "code": 200,
            "status": "Success",
            "message": f"File with id {file_id} deleted successfully."
        }, status=200)

    except Exception as e:
        return Response({
            "code": 500,
            "status": "Error",
            "message": "Internal server error while deleting file.",
            "error": str(e)
        }, status=500)


@api_view(['GET'])
@permission_classes([AllowAny])
def get_file_search_suggestions(request):
    query = request.GET.get('query', '').strip()

    if not query:
        return Response({
            "code": 400,
            "status": "Error",
            "message": "Query parameter is required."
        }, status=400)

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        sql = """
            SELECT TOP 10 file_name, file_type, description, category, tags
            FROM dbo.knowledge_center
            WHERE file_name LIKE ? 
               OR file_type LIKE ? 
               OR description LIKE ? 
               OR category LIKE ? 
               OR tags LIKE ?
        """
        param = f"%{query}%"
        cursor.execute(sql, (param, param, param, param, param))

        suggestions = set()
        rows = cursor.fetchall()
        for row in rows:
            suggestions.add(row[0])  # file_name
            suggestions.add(row[1])  # file_type
            suggestions.add(row[2])  # description
            suggestions.add(row[3])  # category
            tags = row[4].split(",") if row[4] else []
            for tag in tags:
                if query.lower() in tag.lower():
                    suggestions.add(tag.strip())

        cursor.close()
        conn.close()

        return Response({
            "code": 200,
            "status": "Success",
            "data": list(suggestions)
        })

    except Exception as e:
        return Response({
            "code": 500,
            "status": "Error",
            "message": str(e)
        }, status=500)

@api_view(['POST'])
@permission_classes([AllowAny])
def search_files_by_terms(request):
    search_terms = request.data  # expecting a list of strings

    if not isinstance(search_terms, list) or not search_terms:
        return Response({
            "code": 400,
            "status": "Error",
            "message": "Request body must be a non-empty list of search terms."
        }, status=400)

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        conditions = []
        params = []

        for term in search_terms:
            like_term = f"%{term.strip()}%"
            conditions.extend([
                "file_name LIKE ?",
                "file_type LIKE ?",
                "description LIKE ?",
                "category LIKE ?",
                "tags LIKE ?"
            ])
            params.extend([like_term] * 5)

        sql = f"""
            SELECT id, file_name, file_path, file_type, description, category, tags
            FROM dbo.knowledge_center
            WHERE {' OR '.join(conditions)}
        """

        cursor.execute(sql, params)
        rows = cursor.fetchall()

        result = []
        for row in rows:
            result.append({
                "id": row[0],
                "file_name": row[1],
                "file_path": row[2],
                "file_type": row[3],
                "description": row[4],
                "category": row[5],
                "tags": row[6],
            })

        cursor.close()
        conn.close()

        return Response({
            "code": 200,
            "status": "Success",
            "data": result
        })

    except Exception as e:
        return Response({
            "code": 500,
            "status": "Error",
            "message": str(e)
        }, status=500)
    
# ============ ( Send OTP )============

@api_view(["POST"])
@permission_classes([AllowAny])
def send_otp_email(request):

    try:
        email = request.data.get("email")
        if not email:
            return Response({"code": 400, "status": "Failure", "message": "Email is required"}, status=400)
        # Generate OTP Rndomly of 4 digit
        otp = str(random.randint(1000, 9999))
        # Store OTP in Redis cache for 2 minutes
        cache.set(f"otp_{email}", otp, timeout=120)  # 120 seconds = 2 minutes

        # HTML content
        html_message = f"""
            <div style="font-family: Arial, sans-serif; padding: 20px;">
                <h2 style="color: #2e7d32;">Password Reset OTP</h2>
                <p>Hello,</p>
                <p>Your OTP for password reset is:</p>
                <div style="margin: 20px 0;">
                    <a href="#" style="
                        background-color: #4CAF50;
                        color: white;
                        padding: 10px 20px;
                        text-align: center;
                        text-decoration: none;
                        display: inline-block;
                        font-size: 20px;
                        border-radius: 5px;
                        font-weight: bold;
                    ">{otp}</a>
                </div>
                <p>This OTP will expire in <strong>2 minutes</strong>.</p>
                <p>If you did not request this, please ignore this email.</p>
                <br/>
                <p>Regards,<br/>ABFRL</p>
            </div>
        """

        # Send the email
        send_mail(
            subject="Your OTP for Password Reset",
            message=f"Your OTP is {otp}. It will expire in 2 minutes.",  # fallback plain text
            from_email="no-reply@yourdomain.com",
            recipient_list=[email],
            fail_silently=False,
            html_message=html_message,  # This adds the decorated email
        )

        return Response({"code": 200, "status": "Success", "message": "OTP sent successfully"})

    except Exception as e:
        return Response({"code": 500, "status": "Error", "message": str(e)}, status=500)
    
# ==================== ( Verify email OTP ) ================

@api_view(["POST"])
@permission_classes([AllowAny])
def verify_email_otp(request):
    try:
        email = request.data.get("email")
        otp_input = request.data.get("otp")

        if not email or not otp_input:
            return Response({"code": 400, "status": "Failure", "message": "Email and OTP are required"}, status=400)

        # Get OTP from Redis
        stored_otp = cache.get(f"otp_{email}")

        if stored_otp is None:
            return Response({"code": 401, "status": "Failure", "message": "OTP expired or not found"}, status=401)

        if otp_input != stored_otp:
            return Response({"code": 403, "status": "Failure", "message": "Invalid OTP"}, status=403)

        # Optional: delete OTP after verification
        cache.delete(f"otp_{email}")

        return Response({"code": 200, "status": "Success", "message": "OTP verified successfully"})

    except Exception as e:
        return Response({"code": 500, "status": "Error", "message": str(e)}, status=500)

#=============== ( Reset Password ) ===============================

@api_view(["POST"])
@permission_classes([AllowAny])
def reset_password(request):
    try:
        email = request.data.get("email")
        new_password = request.data.get("newPassword")
        vendorCode= request.data.get("vendorCode")

        if not email or not new_password or not vendorCode:
            return Response({'code': 400, 'message': 'Email vendorCode and password are required'}, status=400)

        hashed_password = make_password(new_password)

        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("""
                UPDATE tbl_mVendor
                SET password = ?
                WHERE email = ? AND vendorCode = ?
            """, [hashed_password, email, vendorCode])
            conn.commit()
        return Response({'code': 200, 'message': 'Password reset successful'}, status=200)

    except Exception as e:
        return Response({'code': 500, 'message': str(e)}, status=500)
    

@api_view(["POST"])
@permission_classes([AllowAny])
def check_mobile_number(request):
    mobile = request.data.get("mobile")

    if not mobile:
        return Response({"error": "Mobile number is required"}, status=400)

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        print("Checking mobile:", mobile)

        # ✅ Correct table and column name
        query = "SELECT COUNT(*) FROM tbl_xFranchiseeVendor WHERE mobileNumber = ?"
        cursor.execute(query, (mobile,))
        result = cursor.fetchone()

        exists = result[0] > 0  # If count > 0, number exists
        return Response({"exists": exists}) # true or false

    except Exception as e:
        print("DB Error:", e)
        return Response({"error": "Database error occurred"}, status=500)

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

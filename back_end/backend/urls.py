from django.contrib import admin
from django.urls import path, include
from api.views import (
    CreateUserView, user_login, user_login_otp, store_detail, ledger_detail, all_store_detail, commission_detail, 
    credit_debit, get_all_tds_details, get_cmr_details, get_all_user_details, get_user_detail,
    add_user_details, delete_user_detail, edit_user_detail, get_all_franchisee_details, add_franchisee_details,
    delete_franchisee_detail, get_franchisee_detail, update_specific_franchisee, create_alert, get_all_alerts,
    franchisee_vendor_mapping, get_all_vendors, get_all_franchisees, get_franchisee_details, upload_cmr_ndc_file,
    get_vendor_with_franchisee, get_generic_alert, upload_knowledge_center_file, get_knowledge_center_files,
    delete_knowledge_center_file, get_file_search_suggestions, search_files_by_terms, send_otp_email,verify_email_otp,
    reset_password,check_mobile_number, test)

from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from django.conf import settings
from django.conf.urls.static import static
urlpatterns = [
    path('admin/', admin.site.urls),
    path("api/user/register/", CreateUserView.as_view(), name="register"),
    path("api/user/test/", test, name="test"),
    path("api/user/login/", user_login, name="login"),
    path("api/check-mobile-number/", check_mobile_number, name="check_mobile_number"),
    path("api/forgot-password/send-otp", send_otp_email, name="send-otp"),
    path("api/forgot-password/verify-email-otp", verify_email_otp, name="verify-email-otp"),
    path("api/forgot-password/reset-password", reset_password, name="reset-password"),
    path("api/user/loginOtp/", user_login_otp, name="loginOtp"),
    path("api/user/getstoredetails/", store_detail, name="getstoredetails"),
    path("api/user/getledgerdetails/", ledger_detail, name="getledgerdetails"),
    path("api/user/getallstoredetails/", all_store_detail, name="getallstoredetails"),
    path("api/user/getcommissiondetails/", commission_detail, name="getcommissiondetails"),
    path("api/user/getcreditdebit/", credit_debit, name="getcreditdebit"),
    path("api/user/getallTdsDetails/", get_all_tds_details, name="getallTdsDetails"),
    path("api/user/getCmrDetails/", get_cmr_details, name="getCmrDetails"),
    path("api/getvendorwithfranchisee/", get_vendor_with_franchisee, name="getvendorwithfranchisee"),
#Admin API User
    path("api/admin/getalluserDetails/", get_all_user_details, name="getalluserDetails"),
    path("api/admin/getuserdetails/<str:vendorCode>/", get_user_detail, name="getuserdetails"),
    path("api/admin/adduserdetails/", add_user_details, name="adduserdetails"),
    path("api/admin/deleteUserdetails/<int:vendorUID>/<int:vendorCode>/", delete_user_detail, name="deleteUserdetails"),
    path("api/admin/editUserdetails/<str:vendorCode>/", edit_user_detail, name="editUserdetails"),
#Admin API Franchisee
    path("api/admin/getallfranchiseeDetails/", get_all_franchisee_details, name="getallfranchiseeDetails"),
    path("api/admin/getallvendors/", get_all_vendors, name="getallvendors"),
    path("api/admin/getallfranchisees/", get_all_franchisees, name="getallfranchisees"),
    path("api/admin/getfranchiseedetails/<int:mobileNumber>/", get_franchisee_detail, name="getfranchiseedetails"),
    path("api/admin/updatespecificfranchisee/<int:mobileNumber>/", update_specific_franchisee, name="updatespecificfranchisee"),
    path("api/admin/addfranchiseeDetails/", add_franchisee_details, name="addfranchiseeDetails"),
    path("api/admin/deletefranchiseedetails/<int:mobileNumber>/", delete_franchisee_detail, name="deletefranchiseedetails"),
    path("api/admin/franchiseevendormapping/", franchisee_vendor_mapping, name="franchiseevendormapping"),
    path("api/getfranchiseedetails/", get_franchisee_details, name="getfranchiseedetails"),
    # path("api/admin/getfranchiseedetails/", get_franchisee_details, name="getfranchiseedetails"),
    path("api/admin/uploadcmrndcfile/", upload_cmr_ndc_file, name="uploadcmrndcfile"),

#Admin API Alert
    path("api/admin/createalert/", create_alert, name="create_alert"),
    path("api/user/getallalerts/", get_all_alerts, name="getallalerts"),
    path("api/admin/getGenericAlert/", get_generic_alert, name="getGenericAlert"),

#Admin API Knowledge Center
    path("api/admin/uploadKnowledgeCenterFile/", upload_knowledge_center_file, name="uploadKnowledgeCenterFile"),
    path("api/getKnowledgeCenterFiles/", get_knowledge_center_files, name="getKnowledgeCenterFiles"),
    # path("api/getKnowledgeCenterFiles/", get_knowledge_center_files, name="getKnowledgeCenterFiles"),
    path("api/admin/deleteKnowledgeCenterFile/<int:file_id>/", delete_knowledge_center_file, name="deleteKnowledgeCenterFile"),
    path("api/admin/getFileSearchSuggestions/", get_file_search_suggestions, name="getFileSearchSuggestions"),
    path("api/searchFilesByTerms/", search_files_by_terms, name="searchFilesByTerms"),

    path("api/token/", TokenObtainPairView.as_view(), name="get_token"),
    path("api/token/refresh/", TokenRefreshView.as_view(), name="refresh"),
    path("api-auth/", include("rest_framework.urls")),
]

# Serve media files during development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.MEDIA_URL_1, document_root=settings.MEDIA_ROOT_1)
    urlpatterns += static(settings.MEDIA_URL_2, document_root=settings.MEDIA_ROOT_2)
    urlpatterns += static(settings.MEDIA_URL_3, document_root=settings.MEDIA_ROOT_3)
    urlpatterns += static(settings.MEDIA_URL_4, document_root=settings.MEDIA_ROOT_4)
    urlpatterns += static(settings.MEDIA_URL_5, document_root=settings.MEDIA_ROOT_5)
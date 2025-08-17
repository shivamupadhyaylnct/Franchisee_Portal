export const config = {

    //admin
    createAlert: 'admin/createalert/',
    getAllFranchisees: 'admin/getallfranchisees/',
    getAllVendors: 'admin/getallvendors/',
    adminGetFranchiseDetails: 'admin/getfranchiseedetails/',
    franchiseVendorMapping: 'admin/franchiseevendormapping/',
    updateSpecificFranchise: 'admin/updatespecificfranchisee/',
    addFranchiseDetails: 'admin/addfranchiseeDetails/',
    deleteFranchiseDetails: 'admin/deletefranchiseedetails/',
    getAllFranchiseDetails: 'admin/getallfranchiseeDetails/',
    editUserdetails: 'admin/editUserdetails/',
    adduserdetails: 'admin/adduserdetails/',
    getuserdetails: 'admin/getuserdetails/',
    deleteUserdetails: 'admin/deleteUserdetails/',
    getalluserDetails: 'admin/getalluserDetails/',
    uploadcmrndcfile :'admin/uploadcmrndcfile/',
    getGenericAlert : `admin/getGenericAlert/`,
    uploadKnowledgeCenterFile : 'admin/uploadKnowledgeCenterFile/',
    deleteKnowledgeCenterFile : "admin/deleteKnowledgeCenterFile/",
    getKnowledgeCenterGeneralFiles : 'getKnowledgeCenterFiles/?category=general',
    getKnowledgeCenterSOPFiles :'getKnowledgeCenterFiles/?category=SOP',
    getKnowledgeCenterFranchiseeFiles : 'getKnowledgeCenterFiles/?category=franchiseeHelpbook',
    getKnowledgeCenterTrainingFiles : 'getKnowledgeCenterFiles/?category=trainingModules',
    searchFilesByTerms: `searchFilesByTerms/`,

    //user
    getallalerts: 'user/getallalerts/',
    getallstoredetails: 'user/getallstoredetails/',
    getCmrDetails: 'user/getCmrDetails/',
    loginOtp: 'user/loginOtp/',
    login: 'user/login/',
    getstoredetails: 'user/getstoredetails/',
    getcommissiondetails: 'user/getcommissiondetails/',
    getcreditdebit: 'user/getcreditdebit/',
    getledgerdetails: 'user/getledgerdetails/',
    getallTdsDetails: 'user/getallTdsDetails/',
    // getKnowledgeCenterGeneralFilesByUser : 'user/getKnowledgeCenterFiles/?category=general',

    //common
    getFranchiseDetails: 'getfranchiseedetails/',
    getVendorWithFranchisee : 'getvendorwithfranchisee/',
    sendOtpToEmail: "forgot-password/send-otp",     // POST { email }
    verifyEmailOtp: "forgot-password/verify-email-otp",   // POST { email, otp }
    resetPassword: "forgot-password/reset-password",      // POST { email, newPassword }
    checkMobileNumber: "check-mobile-number/", // Franchisee login mobile check
}

import { baseURL } from "../base";
import { config } from "../config";
import { toast } from "react-toastify";
import { Formik, Form, Field, ErrorMessage } from 'formik';
import * as Yup from 'yup';
import { IconButton } from '@mui/material';
import { Visibility, VisibilityOff } from '@mui/icons-material';
import { useState } from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";

function changePassword() {
    const navigate = useNavigate();
    const user = localStorage.getItem("user_details");
    const userDetails = JSON.parse(user)
    // console.log(userDetails[0]?.UserName);
    const vendorCode = userDetails[0]?.UserName
    const email = userDetails[0]?.EmailId //Extract email in the form of string from an array

    const userName = userDetails?.[0]?.UserName;
    const profileRoute = userName === "ADMIN" ? "/admin/dashboard" : "/user/dashboard";

    const [showPassword, setShowPassword] = useState(false);
    const [showConfirmPassword, setShowConfirmPassword] = useState(false);
    

    const handleResetPassword = async (values) => {
        const { newPassword } = values;
          console.log("user Email is :",email)
          console.log("new Password is :",newPassword)
          console.log("vendor Code is :",vendorCode)

        if (!newPassword )
            return toast.error("Password Required required");
        if(!email)
            return toast.error("Email is Required");


    try {
        const response = await axios.post(`${baseURL}${config.resetPassword}`, {
          email,
          vendorCode,
          newPassword,
        });

        if (response.data.code === 200) {
            toast.success("Password reset successful");
            setTimeout(()=>{
               navigate(profileRoute);
            },3500)
        } else {
          toast.error("Password Reset failed");
        }
    } catch (err) {
      console.error("Error resetting password : ", err.response?.data || err.message)
      toast.error("Error resetting password");
    }
  };

//=========== (Validation ) ==================
   const validationSchema = Yup.object().shape({
    newPassword: Yup.string()
      .matches(
        /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/,
        "Must contain 8 characters: 1 uppercase, 1 lowercase, 1 number, 1 special char"
      )
      .required("Password is required"),
    confirmNewPassword: Yup.string()
      .oneOf([Yup.ref('newPassword'), null], "Passwords must match")
      .required("Confirm Password is required"),
  });

  return (
           <div id="content" className="main-content" >
                <div className="layout-px-spacing"  >
                    <div className="middle-content container-xxl p-0 mt-3" style={{ backgroundColor: 'white', color: 'black' }} >
                        <div className="col-xl-12 col-lg-12 col-md-12 layout-spacing">
                            <div className="section general-info" >
                                <div className="info" >
                                    <h3 className="inv-title mb-2 pb-3 pt-3" >Reset Password</h3>
                                    <div className="row">
                                        <div className="container mt-5">
                                        <div className="row justify-content-center">
                                            <div className="col-md-6">
                                            <div className="card shadow-sm">
                                                <div className="card-body">
                                                <h4 className="card-title text-center mb-4">Reset Password</h4>
                                                
                                                <Formik
                                                    initialValues={{ newPassword: '', confirmNewPassword: '' }}
                                                    validationSchema={validationSchema}
                                                    onSubmit={(values) => handleResetPassword(values)}
                                                >
                                                    {({ isValid, dirty }) => (
                                                    <Form>
                                                        {/* New Password */}
                                                        <div className="mb-3">
                                                        <Field name="newPassword">
                                                            {({ field }) => (
                                                            <div className="position-relative">
                                                                <input
                                                                {...field}
                                                                type={showPassword ? "text" : "password"}
                                                                placeholder="New Password"
                                                                className="form-control"
                                                                />
                                                                <IconButton
                                                                onClick={() => setShowPassword((prev) => !prev)}
                                                                style={{ position: "absolute", right: 5, top: 5 }}
                                                                >
                                                                {showPassword ? <VisibilityOff /> : <Visibility />}
                                                                </IconButton>
                                                            </div>
                                                            )}
                                                        </Field>
                                                        <ErrorMessage name="newPassword" component="div" className="text-danger" />
                                                        </div>

                                                        {/* Confirm New Password */}
                                                        <div className="mb-3">
                                                        <Field name="confirmNewPassword">
                                                            {({ field }) => (
                                                            <div className="position-relative">
                                                                <input
                                                                {...field}
                                                                type={showConfirmPassword ? "text" : "password"}
                                                                placeholder="Confirm New Password"
                                                                className="form-control"
                                                                />
                                                                <IconButton
                                                                onClick={() => setShowConfirmPassword((prev) => !prev)}
                                                                style={{ position: "absolute", right: 5, top: 5 }}
                                                                >
                                                                {showConfirmPassword ? <VisibilityOff /> : <Visibility />}
                                                                </IconButton>
                                                            </div>
                                                            )}
                                                        </Field>
                                                        <ErrorMessage name="confirmNewPassword" component="div" className="text-danger" />
                                                        </div>

                                                        {/* Submit Button */}
                                                        <button
                                                        type="submit"
                                                        className="btn btn-success w-100"
                                                        disabled={!(isValid && dirty)}
                                                        >
                                                        Set New Password
                                                        </button>
                                                    </Form>
                                                    )}
                                                </Formik>
                                                </div>
                                            </div>
                                            </div>
                                        </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
  )
}

export default changePassword

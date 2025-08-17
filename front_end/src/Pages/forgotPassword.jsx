import cover from "../../src/assets/img/cover.jpg";
import cover1 from "../../src/assets/img/cover1.jpg";
import cover2 from "../../src/assets/img/cover2.jpg";
import logo from "../../src/assets/img/logo.jpg";

import { useEffect, useState } from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";
import { baseURL } from "../base";
import { config } from "../config";
import { toast } from "react-toastify";
import { Formik, Form, Field, ErrorMessage } from 'formik';
import * as Yup from 'yup';
import { IconButton } from '@mui/material';
import { Visibility, VisibilityOff } from '@mui/icons-material';

function forgotPassword() {
  const [step, setStep] = useState(1); // step1 = email, 2 = OTP, 3 = reset
  const [email, setEmail] = useState("");
  const [otp, setOtp] = useState("");
  const [timer, setTimer] = useState(120); //hardcoded 2 min
  const [isLoading, setIsLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const navigate = useNavigate();

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

  //================== (3 step of Forget password => step1 = email, 2 = OTP, 3 = reset)======================

  const handleSendOtp = async () => {
    if (!email) 
        return toast.error("Email is required");
        console.log(email)
    try {
        setIsLoading(true);
        const response = await axios.post(`${baseURL}${config.sendOtpToEmail}`, { email });
        if (response.data.code === 200) {
            console.log("res ",response.data)
      toast.success("OTP sent to your email");
      setStep(2); // OTP verification process
        } else {
          toast.error("Email not found");
        }
    } catch (err) {
      toast.error("Server error while sending OTP");
    } finally {
      setIsLoading(false);
    }
  };

  const handleVerifyOtp = async () => {
    if (!otp) 
        return toast.error("Enter OTP");
    try {
        setIsLoading(true);
        const response = await axios.post(`${baseURL}${config.verifyEmailOtp}`, { email, otp });
        if (response.data.code === 200) {
      toast.success("OTP verified");
      setStep(3);
        } else {
          toast.error("Invalid OTP");
        }
    } catch (err) {
      toast.error("OTP verification failed");
      console.log(`OTP verification failed: ${err}`)
    } finally {
      setIsLoading(false);
    }
  };

  const handleResetPassword = async (values) => {
    const { newPassword } = values;

    if (!newPassword )
        return toast.error("Password Required required");
    if(!email)
        return toast.error("Email is Required");


    try {
        const response = await axios.post(`${baseURL}${config.resetPassword}`, {
          email,
          newPassword,
        });

        if (response.data.code === 200) {
            toast.success("Password reset successful");
            navigate("/");
        } else {
          toast.error("Reset failed");
        }
    } catch (err) {
      toast.error("Error resetting password");
    }
  };

//   =============( CountDown AND Resend OTP )===========
 useEffect(() => {
        let interval;
        if (step === 2 && timer > 0) {
            interval = setInterval(() => {
                setTimer((prevTime) => prevTime - 1);
            }, 1000);
        }

        if (timer === 0) {
            clearInterval(interval);
            }
        return () => clearInterval(interval);
  }, [step, timer]);


  const formatTime = (seconds) => {
    const mins = Math.floor(seconds / 60)
      .toString()
      .padStart(2, "0");
    const secs = (seconds % 60).toString().padStart(2, "0");
    return `${mins}:${secs}`;

  };

  const handleResendOtp = async () => {
    try {
        const response = await axios.post(`${baseURL}${config.sendOtpToEmail}`, { email });

        if (response.data.code === 200) {
        toast.success("OTP resent successfully!");
        setTimer(120); // reset timer to 2 mins again
        }
    } catch (err) {
        toast.error("Failed to resend OTP.");
    }
};
  return (
    <div className="form">
      {/* <div id="load_screen">
      <div className="loader">
        <div className="loader-content">
          <div className="spinner-grow align-self-center"></div>
        </div>
      </div>
    </div> */}

      <div className="auth-container d-flex">
        <div className="container mx-auto align-self-center">
          <div className="row">
            {/* LEFT IMAGE SECTION */}
            <div className="col-6 d-lg-flex d-none h-100 my-auto top-0 start-0 text-center justify-content-center flex-column">
              <div className="auth-cover-bg-image"></div>
              <div className="auth-overlay"></div>
              <div className="auth-cover">
                <div className="position-relative">
                  <div
                    id="authImageSlider"
                    className="carousel slide carousel-fade"
                    data-bs-ride="carousel"
                    data-bs-interval="3000"
                  >
                    <div className="carousel-inner">
                      <div className="carousel-item active">
                        <img
                          src={cover}
                          className="rounded shadow"
                          alt="auth-img-1"
                        />
                      </div>
                      <div className="carousel-item">
                        <img
                          src={cover1}
                          className="rounded shadow"
                          alt="auth-img-2"
                        />
                      </div>
                      <div className="carousel-item">
                        <img
                          src={cover2}
                          className="rounded shadow"
                          alt="auth-img-3"
                        />
                      </div>
                    </div>
                    <button
                      className="carousel-control-prev"
                      type="button"
                      data-bs-target="#authImageSlider"
                      data-bs-slide="prev"
                    >
                      <span className="carousel-control-prev-icon"></span>
                    </button>
                    <button
                      className="carousel-control-next"
                      type="button"
                      data-bs-target="#authImageSlider"
                      data-bs-slide="next"
                    >
                      <span className="carousel-control-next-icon"></span>
                    </button>
                  </div>
                  <h2 className="mt-5 text-white font-weight-bolder px-2">
                    Aditya Birla Fashion And Retail's vision
                  </h2>
                  <p className="text-white px-2">
                    is to passionately satisfy the Indian consumer’s needs in
                    fashion, style and value, across wearing occasions, in
                    apparels and accessories, by anticipating trends and
                    creating markets with the ultimate purpose of delivering
                    superior value to all stakeholders.
                  </p>
                </div>
              </div>
            </div>

            {/* RIGHT EMAIL INPUT SECTION */}
            <div className="col-xxl-4 col-xl-5 col-lg-5 col-md-8 col-12 d-flex flex-column align-self-center ms-lg-auto me-lg-0 mx-auto d-block">
              <div className="card">
                <div className="card-body">
                  <div className="col-md-12 mb-3">
                    <center>
                      <img
                        src={logo}
                        className="rounded border"
                        width="100px"
                        alt="logo"
                      />
                    </center>
                  </div>

{/* EMAIL VERIFICATION INPUT */}
                  {step === 1 && (
                    <>
                      <div className="col-md-12">
                        <div className="mb-3">
                          <label className="form-label">
                            Email Verification
                          </label>
                          <div className="input-group">
                            <span className="input-group-text" id="inputGroupPrepend2" >
                                 <i className="fa fa-envelope"></i> 
                            </span>
                            <input
                              type="email"
                              placeholder="Enter your email"
                              name="email"
                              className="form-control"
                              aria-describedby="inputGroupPrepend2"
                              value={email}
                              onChange={(e) => setEmail(e.target.value)}
                            />
                          </div>
                        </div>
                      </div>

                      <div className="col-12">
                        <div className="mb-1">
                          <button
                            type="submit"
                            className="btn btn-primary w-100"
                            onClick={handleSendOtp}
                            disabled={isLoading}
                          >
                            {" "}
                            {isLoading ? "Waiting..." : "Send OTP"}{" "}
                          </button>
                        </div>
                      </div>
                    </>
                  )}
    {/* OTP verification process */}
                  {step === 2 && (
                    <>
                    <div className="col-md-12">
                        <div className="mb-3">
                          <label className="form-label"> Verify OTP </label>
                             {timer > 0 ? (
                                <p className="text-muted">OTP expires in: {formatTime(timer)}</p>
                                ) : (
                            <>
                                <p className="text-danger mt-2"> OTP has expired </p>
                                <button className="btn btn-link text-primary p-0" onClick={handleResendOtp}>
                                Click here to resend OTP
                                </button>
                            </>
                            )}
                          <div className="input-group">
                            <span className="input-group-text" id="inputGroupPrepend2" >
                                 <i className="fa fa-envelope"></i> 
                            </span>
                            <input
                              type="text"
                              placeholder="Enter OTP"
                              className="form-control"
                              aria-describedby="inputGroupPrepend2"
                              value={otp}
                              onChange={(e) => setOtp(e.target.value)}
                            />
                          </div>
                        </div>
                      </div>

                    <div className="col-12">
                        <div className="mb-1">
                          <button type="submit" 
                                  className="btn btn-primary w-100" 
                                  onClick={handleVerifyOtp}
                                  disabled={isLoading}
                             > 
                             {isLoading ? "Waiting..." : "Verify OTP"}
                          </button>
                        </div>
                      </div>

                    </>
                  )}
                  {/* password reset Process */}
                  {step === 3 && (
                    <>
                    <Formik
                    initialValues={{ newPassword: '', confirmNewPassword: '' }}
                    validationSchema={validationSchema}
                    onSubmit={(values) => {
                        handleResetPassword(values);
                    }}
                    >
                    {({ isValid, dirty}) => (
                        <Form className="row">
                        <div className="col-md-12">
                            <div className="mb-3">
                            <h3 className="form-label">Reset Password</h3>

                            <div className="input-group mb-2">
                                <Field name="newPassword">
                                {({ field }) => (
                                    <div style={{ position: 'relative', width: '100%' }}>
                                    <input
                                        {...field}
                                        type={showPassword ? "text" : "password"}
                                        placeholder="New Password"
                                        className="form-control"
                                    />
                                    <IconButton
                                        onClick={() => setShowPassword(prev => !prev)}
                                        style={{ position: 'absolute', right: 5, top: 5 }}
                                    >
                                        {showPassword ? <VisibilityOff /> : <Visibility />}
                                    </IconButton>
                                    </div>
                                )}
                                </Field>
                            </div>
                            <ErrorMessage name="newPassword" component="div" className="text-danger" />

                            <div className="input-group mt-2">
                                <Field name="confirmNewPassword">
                                {({ field }) => (
                                    <div style={{ position: 'relative', width: '100%' }}>
                                    <input
                                        {...field}
                                        type={showConfirmPassword ? "text" : "password"}
                                        placeholder="Confirm new Password"
                                        className="form-control"
                                    />
                                    <IconButton
                                        onClick={() => setShowConfirmPassword(prev => !prev)}
                                        style={{ position: 'absolute', right: 5, top: 5 }}
                                    >
                                        {showConfirmPassword ? <VisibilityOff /> : <Visibility />}
                                    </IconButton>
                                    </div>
                                )}
                                </Field>
                            </div>
                            <ErrorMessage name="confirmNewPassword" component="div" className="text-danger" />

                            </div>
                        </div>

                        <div className="col-12">
                            <div className="mb-1">
                            <button type="submit" 
                                    className="btn btn-success mt-2 w-100"
                                    disabled={!(isValid && dirty)}>
                                Set New Password
                            </button>
                            </div>
                        </div>
                        </Form>
                    )}
                    </Formik>

                    </>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default forgotPassword;

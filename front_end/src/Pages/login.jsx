import cover from "../../src/assets/img/cover.jpg";
import cover1 from "../../src/assets/img/cover1.jpg";
import cover2 from "../../src/assets/img/cover2.jpg";
import logo from "../../src/assets/img/logo.jpg";
import divider2 from "../../src/assets/img/divider2.png";

import { useState, useEffect, useRef } from "react";
import { Link, useNavigate } from "react-router-dom";
import axios from "axios";

import { Formik, Form, Field, ErrorMessage } from "formik";
import * as Yup from "yup";
import { toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";

import { baseURL } from "../base";
import { config } from "../config";

function Login() {
  const [mobileNumber, setMobileNumber] = useState("");
  const [error, setError] = useState("");
  const [otp, setOtp] = useState(["", "", "", ""]);
  const [isHidden, setIsHidden] = useState([false, false, false, false]);
  const inputRefs = [useRef(), useRef(), useRef(), useRef()];



    const handleMobileChange = (e) => {
        const value = e.target.value;
        const cleaned = value.replace(/\D/g, ""); // \D = non-digit

        // Only update state if length is ≤ 10
        if (cleaned.length <= 10) {
          setMobileNumber(cleaned);
          if (cleaned.length === 10 && validateMobileNumber(cleaned)) {
            setError("");
          }
        }
      };

    const validateMobileNumber = (number) => {
      const mobileRegex = /^[0-9]{10}$/;
      return mobileRegex.test(number);
    };



  const handleChange = (index, value) => {
    if (!/^\d?$/.test(value)) return;

    const newOtp = [...otp];
    newOtp[index] = value || "";
    setOtp(newOtp);

    if (value !== "" && index < inputRefs.length - 1) {
      inputRefs[index + 1].current.focus();
    }

    if (value !== "") {
      setTimeout(() => {
        setIsHidden((prev) => {
          const newHidden = [...prev];
          newHidden[index] = true;
          return newHidden;
        });
      }, 300);
    }
  };

  const handleKeyDown = (index, event) => {
    if (event.key === "Backspace") {
      if (otp[index] !== "") {
        const newOtp = [...otp];
        newOtp[index] = "";
        setOtp(newOtp);
        setIsHidden((prev) => {
          const newHidden = [...prev];
          newHidden[index] = false;
          return newHidden;
        });
      } else if (index > 0) {
        inputRefs[index - 1].current.focus();
      }
    }
  };

  useEffect(() => {
    // Remove Loader after page loads
    localStorage.removeItem("mobile");
    const loadScreen = document.getElementById("load_screen");
    if (loadScreen) {
      loadScreen.style.display = "none"; // Hide instead of removing (safer)
    }

    // Layout Configuration
    const layoutName = "Horizontal Light Menu";

    const settingsObject = {
      admin: "Cork Admin Template",
      settings: {
        layout: {
          name: layoutName,
          toggle: true,
          darkMode: false,
          boxed: true,
          logo: {
            darkLogo: `${logo}`,
            lightLogo: `${logo}`,
          },
        },
      },
      reset: false,
    };

    // Reset theme if necessary
    if (settingsObject.reset) {
      localStorage.clear();
    }

    let corkThemeObject;
    const storedTheme = localStorage.getItem("theme");

    if (!storedTheme) {
      corkThemeObject = settingsObject;
    } else {
      try {
        const parsedTheme = JSON.parse(storedTheme);
        if (
          parsedTheme.admin === "Cork Admin Template" &&
          parsedTheme.settings.layout.name === layoutName
        ) {
          corkThemeObject = parsedTheme;
        } else {
          corkThemeObject = settingsObject;
        }
      } catch (error) {
        corkThemeObject = settingsObject;
      }
    }

    // Save to localStorage
    localStorage.setItem("theme", JSON.stringify(corkThemeObject));

    // Apply layout settings
    if (corkThemeObject.settings.layout.boxed) {
      document.body.classList.add("layout-boxed");
    } else {
      document.body.classList.remove("layout-boxed");
    }
  }, []);

  //============= (Formik Details ) ========================
  const initialValues = { email: "", password: "", };
  const navigate = useNavigate();

  const validationSchema = Yup.object({
    email: Yup.string().required("User Name is required"),
    password: Yup.string().required("Password is required"),
  });

  // ===================== (Normal Login) ==========================

  
   const handleSubmit = async (values, { setSubmitting }) => {
    try {
      
      const response = await axios.post(`${baseURL}${config.login}`, {
        username: values.email,
        password: values.password,
      });

      if (response.data.code === 404) {
         toast.error("User not found");
      }
      if (response.data.code === 401) {
          console.log("code is :",response.data.code);
          toast.error("Incorrect Password"); 
      }

      if (response.data.code === 201) {
          const user_details = response?.data?.user_details;
          localStorage.setItem( "user_details", JSON.stringify(user_details));
          console.log("user_details is =>",user_details)

          const userType = user_details?.[0]?.UserType;
          if (userType === "USER")
            navigate("/user/dashboard", { replace: true });
          else if (userType === "ADMIN")
            navigate("/admin/dashboard", { replace: true });
      }
    } catch (error) {
          if (error.response?.status === 404) {
            toast.error("User not found"); 
          } else if (error.response?.status === 401) {
            toast.error("Incorrect Password");
          } else {
            toast.error(`Error is: ${error.message}`);
          }
          console.error("Error is ", error.message);
    } 
    finally {
      setSubmitting(false);
    }
  };


  
    async function onOTPSend() {
      if (!mobileNumber) {
        setError("Mobile number is required!");
      } else if (!validateMobileNumber(mobileNumber)) {
        setError("Enter a valid 10-digit mobile number.");
      } else {
        setError("");
        try {
          // Send POST request to backend to check if number exists
          const response = await axios.post(`${baseURL}${config.checkMobileNumber}`, {
            mobile: mobileNumber
          });

          if (response.data.exists) {
            // Number exists — move to OTP section
            const loginSection = document.getElementById("loginSection");
            const mobileNumberSection = document.getElementById("mobilenumber");
            const otpSection = document.getElementById("otp");

            mobileNumberSection.classList.add("d-none");
            loginSection.classList.add("d-none");
            otpSection.classList.remove("d-none");

          } else {
            // setError("Mobile number not found in our system.");
            toast.error("Mobile Number not Registered")
          }
          
        } catch (error) {
           console.error("Error checking mobile number:", error);
           setError("Something went wrong. Please try again later.");
        }
      }
    }

  const verifyOTP = async () => {
    const enteredOTP = otp.join("");
    const enteredMOB = mobileNumber.slice(-4);

    if (enteredOTP === enteredMOB) {
      try {
          const response = await axios.post(`${baseURL}${config.loginOtp}`, {
            mobileNumber: mobileNumber,
          });

          if ( response.data.status === "Success" && response.data.data.length > 0 ) {
              let userDetails = response.data.data;
              //   userDetails.user_details[0].UserType = "franchisee"
              localStorage.setItem("mobile", mobileNumber);
              localStorage.setItem("user_details", JSON.stringify(userDetails));
              console.log("All users saved to localStorage:", userDetails);

              //     const user = response.data.data[0]; // get the first user object
              //     const userInfo = {
              //     UserName: user.UserName,
              //     UserType: user.UserType,
              //     EmailId: user.EmailId,
              //     PANNO: user.PANNO
              // };

              navigate("/user/dashboard");
          } else {
            toast.error(response.data.message || "Login failed");
          }
      } catch (err) {
        toast.error("Server error");
      }
    } else {
      toast.error("Please Provide Correct OTP");
    }
  };

  return (
    <div className="form">
      {/* BEGIN LOADER */}
      <div id="load_screen">
        <div className="loader">
          <div className="loader-content">
            <div className="spinner-grow align-self-center"></div>
          </div>
        </div>
      </div>
      {/*  END LOADER */}

      <div className="auth-container d-flex">
        <div className="container mx-auto align-self-center">
          <div className="row">
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
                    Aditya Birla Lifestyle Brand's vision{" "}
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

            <div className="col-xxl-4 col-xl-5 col-lg-5 col-md-8 col-12 d-flex flex-column align-self-center ms-lg-auto me-lg-0 mx-auto d-block">
              <div className="card">
                <div className="card-body">
                  <div className="col-md-12 mb-3">
                    <center>
                      <img src={logo} className="rounded border" width="100px" />{" "}
                    </center>
                  </div>
                  <Formik
                    initialValues={initialValues}
                    validationSchema={validationSchema}
                    onSubmit={handleSubmit}
                  >
                    {({ isSubmitting }) => (
                      <Form className="row" id="loginSection">

                        <div className="col-md-12">
                          <div className="mb-3">
                            <label className="form-label">User Name</label>
                            <div className="input-group">
                              <span className="input-group-text" id="inputGroupPrepend2" > <i className="fa fa-envelope"></i> </span>
                              <Field
                                type="text"
                                name="email"
                                className="form-control"
                                aria-describedby="inputGroupPrepend2"
                              />
                            </div>
                                <ErrorMessage name="email" component="div" className="text-danger" />
                          </div>
                        </div>

                        <div className="col-12">
                          <div className="mb-3">
                            <label className="form-label">Password</label>
                            <div className="input-group">
                              <span className="input-group-text" id="inputGroupPrepend2" > <i className="fa fa-lock"></i> </span>
                              <Field
                                type="password"
                                name="password"
                                className="form-control"
                                aria-describedby="inputGroupPrepend2"
                              />
                            </div>
                              <ErrorMessage name="password" component="div" className="text-danger" />
                          </div>
                        </div>

                        <div className="col-12">
                          <div className="mb-3 text-end">
                            <Link to="/forgotPassword">Forgot Password?</Link>
                          </div>
                        </div>

                        <div className="col-12">
                          <div className="mb-1">
                            <button type="submit" className="btn btn-primary w-100" disabled={isSubmitting} >
                              {isSubmitting ? "Please Wait..." : "Login"}
                            </button>
                          </div>
                        </div>

                        <div className="col-12 mb-3 mt-3">
                          <div className="seperator">
                            <div className="seperator-line">
                              <img src={divider2} alt="Decorative Line" className="decorative-line" />
                              <div className="seperator-text">
                                <span>Or Continue With</span>
                              </div>
                            </div>
                          </div>
                        </div>

                      </Form>
                    )}
                  </Formik>

                  <div className="row" id="mobilenumber">
                    <div className="col-12">
                      <label className="form-label">Mobile Number</label>
                      <div className="input-group">
                        <span className="input-group-text" id="inputGroupPrepend2" > 
                          <i className="fa fa-mobile"></i> 
                        </span>
                          <input
                              type="text"
                              inputMode="numeric"
                              maxLength={10}
                              className={`form-control ${error ? "is-invalid" : ""}`}
                              id="validationDefaultUsername"
                              aria-describedby="inputGroupPrepend2"
                              value={mobileNumber}
                              onChange={handleMobileChange}
                              required
                          />
                        <button className="btn btn-primary" onClick={onOTPSend}>
                          Send OTP
                        </button>
                      </div>
                      {error && <div className="text-danger mt-1">{error}</div>}
                    </div>
                  </div>

                  <div className="row d-none" id="otp">
                    <div className="col-md-12 mb-3 text-center">
                      <h2>2-Step Verification</h2>
                      <p>Enter the code for verification.</p>
                    </div>
                    <div className="d-flex justify-content-center">
                      {otp.map((digit, index) => (
                        <input
                          key={index}
                          type={isHidden[index] ? "password" : "text"} // Hide once entered
                          className="form-control opt-input mx-1 text-center"
                          style={{
                            width: "60px",
                            fontSize: "1.5rem",
                            textAlign: "center",
                          }}
                          value={digit || ""}
                          onChange={(e) => handleChange(index, e.target.value)}
                          onKeyDown={(e) => handleKeyDown(index, e)}
                          maxLength={1}
                          ref={inputRefs[index]}
                        />
                      ))}
                    </div>

                    <div className="col-12 mt-4">
                      <div className="mb-4">
                        <button
                          className="btn btn-primary w-100"
                          onClick={verifyOTP}
                        >
                          VERIFY
                        </button>
                      </div>
                    </div>

                    <div className="col-12">
                      <div className="text-center">
                        <p className="mb-0">
                          Didn't receive the code ?{" "}
                          <a href="#" className="text-primary">
                            Resend
                          </a>
                        </p>
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
  );
}

export default Login;

import React from 'react'
import logo from '../../src/assets/img/logo.jpg';
import profile from '../../src/assets/img/profile-30.png';
import usersvg from '../../src/assets/img/usersvg.svg'
import { Link, useNavigate } from "react-router-dom";

function Header() {
    const user = localStorage.getItem("user_details");
    const mobile = localStorage.getItem("mobile");
    const userDetails = JSON.parse(user)
    // console.log("user details is ",userDetails)
    const navigate = useNavigate();
    const userName = userDetails?.[0]?.UserName;

    // Precompute the profile route based on userName
    const profileRoute = userName === "ADMIN" ? "/admin/profile" : "/user/profile";
    const handleProfileClick = (e) => {
        e.preventDefault();
        navigate(profileRoute);
    };


    return (
        <>
            {/* <!--  BEGIN NAVBAR  --> */}
            <div className="header-container container-xxl">
                <header className="header navbar navbar-expand-sm expand-header">

                    <a className="sidebarCollapse" data-placement="bottom"><svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="feather feather-menu"><line x1="3" y1="12" x2="21" y2="12"></line><line x1="3" y1="6" x2="21" y2="6"></line><line x1="3" y1="18" x2="21" y2="18"></line></svg></a>

                    <ul className="navbar-item theme-brand flex-row  text-center">
                        <li className="nav-item theme-logo">
                            <Link to ="#">
                                <img src={logo} className="navbar-logo" alt="logo" />
                            </Link>
                        </li>
                        <li className="nav-item theme-text">
                            <Link to ="#" className="nav-link"> Franchisee Portal </Link>
                        </li>
                    </ul>



                    <ul className="navbar-item flex-row ms-lg-auto ms-0 action-area">

                        <li className="nav-item theme-toggle-item d-none">
                            <a className="nav-link theme-toggle">
                                <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="feather feather-moon dark-mode"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>
                                <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="feather feather-sun light-mode"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>
                            </a>
                        </li>

                        <li className="nav-item">
                            <div className="user-profile-section">
                                <div className="media mx-auto">
                                    <div className="emoji me-2">
                                        &#x1F44B;
                                    </div>
                                    <div className="media-body">
                                        {/* <h5>{userDetails?.data?.[0]?.UserName || userDetails.UserName}</h5> */}
                                        {mobile || userName || "Guest"}
                                    </div>
                                </div>
                            </div>
                        </li>

                        <li className="nav-item dropdown user-profile-dropdown  order-lg-0 order-1">
                            <a className="nav-link dropdown-toggle user" id="userProfileDropdown" data-bs-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                                <div className="avatar-container">
                                    <div className="avatar avatar-sm avatar-indicators avatar-online">
                                        <img alt="avatar" src={usersvg} className="rounded-circle" />
                                    </div>
                                </div>
                            </a>

                            <div className="dropdown-menu position-absolute" aria-labelledby="userProfileDropdown">
                                <div className="user-profile-section">
                                    <div className="media mx-auto">
                                        <div className="emoji me-2">
                                            &#x1F44B;
                                        </div>
                                        <div className="media-body">
                                            {/* <h5>{userDetails?.data?.[0]?.UserName || userDetails.UserName}</h5> */}
                                            {mobile || userName || "Guest"}
                                            {/* <!-- <p>Project Leader</p> --> */}
                                        </div>
                                    </div>
                                </div>
                                <div className="dropdown-item">
                                    <Link to ="#" onClick={handleProfileClick} style={{ cursor: "pointer" }}>
                                        <svg
                                            xmlns="http://www.w3.org/2000/svg"
                                            width="24"
                                            height="24"
                                            viewBox="0 0 24 24"
                                            fill="none"
                                            stroke="currentColor"
                                            strokeWidth="2"
                                            strokeLinecap="round"
                                            strokeLinejoin="round"
                                            className="feather feather-user">
                                            <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2">
                                            </path><circle cx="12" cy="7" r="4"></circle></svg>
                                        <span>Profile</span>
                                    </Link>
                                </div>
                                 <div className="dropdown-item">
                                    <Link to ="/admin/changePassword" style={{ cursor: "pointer" }}>
                                        <svg xmlns="http://www.w3.org/2000/svg" 
                                             width="32" 
                                             height="32" 
                                             viewBox="0 0 32 32">
                                                <path fill="currentColor" d="M21 2a8.998 8.998 0 0 0-8.612 11.612L2 24v6h6l10.388-10.388A9 9 0 1 0 21 2m0 16a7 7 0 0 1-2.032-.302l-1.147-.348l-.847.847l-3.181 3.181L12.414 20L11 21.414l1.379 1.379l-1.586 1.586L9.414 23L8 24.414l1.379 1.379L7.172 28H4v-3.172l9.802-9.802l.848-.847l-.348-1.147A7 7 0 1 1 21 18"/>
                                                <circle cx="22" cy="10" r="2" fill="currentColor"/>
                                        </svg>
                                        <span>Change Password</span>
                                    </Link>
                                </div>
                                <div className="dropdown-item">
                                    <Link to="/" style={{ cursor: "pointer" }}>
                                        <svg xmlns="http://www.w3.org/2000/svg"
                                            width="24" height="24"
                                            viewBox="0 0 24 24"
                                            fill="none"
                                            stroke="currentColor"
                                            strokeWidth="2"
                                            strokeLinecap="round"
                                            strokeLinejoin="round"
                                            className="feather feather-log-out">
                                            <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path>
                                            <polyline points="16 17 21 12 16 7"></polyline>
                                            <line x1="21" y1="12" x2="9" y2="12"></line></svg>
                                        <span>Log Out</span>
                                    </Link>
                                </div>
                            </div>

                        </li>
                    </ul>
                </header>
            </div>
            {/* <!--  END NAVBAR  --> */}
        </>
    )
}

export default Header
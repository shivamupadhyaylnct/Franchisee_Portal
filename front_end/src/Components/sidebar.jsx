
import logo from '../../src/assets/img/logo.jpg';
import { Link, useLocation } from "react-router-dom";

const Sidebar = () => {
    const location = useLocation();
    return (
        <>
            <div className="overlay"></div>
            <div className="search-overlay"></div>
            <div className="sidebar-wrapper sidebar-theme">
                <nav id="sidebar">

                    <div className="navbar-nav theme-brand flex-row  text-center">
                        <div className="nav-logo">
                            <div className="nav-item theme-logo">
                                <Link to="#">
                                    <img src={logo} className="navbar-logo" alt="logo" />
                               </Link>
                            </div>
                            <div className="nav-item theme-text">
                                <Link to="#" className="nav-link"> Franchise Portal</Link>
                            </div>
                        </div>
                        <div className="nav-item sidebar-toggle">
                            <div className="btn-toggle sidebarCollapse">
                                <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="feather feather-chevrons-left">
                                    <polyline points="11 17 6 12 11 7"></polyline>
                                    <polyline points="18 17 13 12 18 7"></polyline>
                                </svg>
                            </div>
                        </div>
                    </div>
                    <div className="shadow-bottom"></div>

                    <ul className="list-unstyled menu-categories" id="accordionExample">
                            <li className={`menu ${location.pathname === "/user/dashboard" ? "active" : ""}`}>
                                <Link to="/user/dashboard" className="dropdown-toggle">
                                    <div className="">
                                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="feather feather-home">
                                            <path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"></path>
                                            <polyline points="9 22 9 12 15 12 15 22"></polyline>
                                        </svg>
                                        <span>Dashboard</span>
                                    </div>
                                </Link>
                            </li>


                            <li className={`menu ${location.pathname === "/user/store" ? "active" : ""}`}>
                                <Link to="/user/store" className="dropdown-toggle">
                                    <div className="">
                                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="feather feather-cpu">
                                            <rect x="4" y="4" width="16" height="16" rx="2" ry="2"></rect> <rect x="9" y="9" width="6" height="6"></rect>
                                            <line x1="9" y1="1" x2="9" y2="4"></line> <line x1="15" y1="1" x2="15" y2="4"></line>
                                            <line x1="9" y1="20" x2="9" y2="23"></line> <line x1="15" y1="20" x2="15" y2="23"></line>
                                            <line x1="20" y1="9" x2="23" y2="9"></line> <line x1="20" y1="14" x2="23" y2="14"></line>
                                            <line x1="1" y1="9" x2="4" y2="9"></line> <line x1="1" y1="14" x2="4" y2="14"></line>
                                        </svg>
                                        <span>Stores</span>
                                    </div>
                                </Link>
                            </li>
                            
                            <li className={`menu ${location.pathname.startsWith("/user/statements") ? "active" : ""}`}>
                                <Link to="#" data-bs-toggle="dropdown" aria-expanded="false" className="dropdown-toggle">
                                    <div className="">
                                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="feather feather-layers"><polygon points="12 2 2 7 12 12 22 7 12 2"></polygon><polyline points="2 17 12 22 22 17"></polyline><polyline points="2 12 12 17 22 12"></polyline></svg>
                                        <span>Statements</span>
                                    </div>
                                    <div>
                                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="feather feather-chevron-right"><polyline points="9 18 15 12 9 6"></polyline></svg>
                                    </div>
                               </Link>
                            <ul className="dropdown-menu submenu list-unstyled" id="tables" data-bs-parent="#accordionExample">
                                <li className={`${location.pathname === "/user/statements/commission" ? "active" : ""}`}>
                                    <Link to="/user/statements/commission"> Commission</Link>
                                </li>
                                <li className={`${location.pathname === "/user/statements/ledger" ? "active" : ""}`}>
                                    <Link to="/user/statements/ledger"> Ledger</Link>
                                </li>
                                <li className={`${location.pathname === "/user/statements/creditdebit" ? "active" : ""}`}>
                                    <Link to="/user/statements/creditdebit"> Credit and Debit Notes</Link>
                                </li>
                         
                                <li className={`${location.pathname === "/user/statements/tdsCertificates" ? "active" : ""}`}>
                                    <Link to="/user/statements/tdsCertificates"> TDS Certificates</Link>
                                </li>
                                {/*<li className={`${location.pathname === "/user/statements/securitydeposit" ? "active" : ""}`}>
                                    <Link to="/user/statements/securitydeposit"> Security Deposit</Link>
                                </li>*/}



                            </ul>
                        </li>

                        <li className={`menu ${location.pathname === "/user/declaration" ? "active" : ""}`}>
                            <Link to="/user/declaration" className="dropdown-toggle">
                                <div className="">
                                    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="feather feather-clipboard">
                                    <path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2">
                                    </path><rect x="8" y="2" width="8" height="4" rx="1" ry="1"></rect></svg>
                                    <span>Declarations</span>
                                </div>
                                <div>
                                    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="feather feather-chevron-right"><polyline points="9 18 15 12 9 6"></polyline></svg>
                                </div>
                           </Link>
                        </li>

                        <li className={`menu ${location.pathname === "/user/support" ? "active" : ""}`}>
                            <Link to="/user/support" className="dropdown-toggle">
                                <div className="">
                                    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="feather feather-zap"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>
                                    <span>Support</span>
                                </div>
                                <div>
                                    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="feather feather-chevron-right"><polyline points="9 18 15 12 9 6"></polyline></svg>
                                </div>
                           </Link>

                        </li>

                        <li className={`menu ${location.pathname === "/user/knowledgecenter" ? "active" : ""}`}>
                            <Link to="/user/knowledgecenter" className="dropdown-toggle">
                                <div className="">
                                    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="feather feather-box"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"></path><polyline points="3.27 6.96 12 12.01 20.73 6.96"></polyline><line x1="12" y1="22.08" x2="12" y2="12"></line></svg>
                                    <span>Knowledge Center</span>
                                </div>
                                <div>
                                    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="feather feather-chevron-right"><polyline points="9 18 15 12 9 6"></polyline></svg>
                                </div>
                           </Link>
                        </li>
                    </ul>
                </nav>
            </div>
        </>
    );
};

export default Sidebar;

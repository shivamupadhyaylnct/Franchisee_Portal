
import logo from '../../../src/assets/img/logo.jpg';
import { Link, useLocation} from "react-router-dom";

function adminSidebar() {
        const location = useLocation();
    
  return (
          <>
               {/* <div className="overlay"></div>
               <div className="search-overlay"></div> */}
               <div className="sidebar-wrapper sidebar-theme">
                   <nav id="sidebar">

                       <div className="navbar-nav theme-brand flex-row  text-center">
                           <div className="nav-logo">
                               <div className="nav-item theme-logo">
                                   <a href="#">
                                       <img src={logo} className="navbar-logo" alt="logo" />
                                   </a>
                               </div>
                               <div className="nav-item theme-text">
                                   <a href="#" className="nav-link"> Franchise Portal </a>
                               </div>
                           </div>
                           <div className="nav-item sidebar-toggle">
                               <div className="btn-toggle sidebarCollapse">
                                   <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="feather feather-chevrons-left">
                                    <polyline points="11 17 6 12 11 7"></polyline><polyline points="18 17 13 12 18 7"></polyline>
                                   </svg>
                               </div>
                           </div>
                       </div>

                       <ul className="list-unstyled menu-categories" id="accordionExample">
                           <li className={`menu ${location.pathname === "/admin/dashboard" ? "active" : ""}`}>
                               <Link to="/admin/dashboard" className="dropdown-toggle">
                                   <div className="">
                                       <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="feather feather-zap"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>
                                       <span>Dashboard</span>
                                   </div>
                                   {/* <div>
                                       <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="feather feather-chevron-right"><polyline points="9 18 15 12 9 6"></polyline></svg>
                                   </div> */}
                               </Link>
                           </li>
                           <li className={`menu ${location.pathname === "/admin/user" ? "active" : ""}`}>
                               <Link to="/admin/user" className="dropdown-toggle">
                                   <div className="">
                                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24">
                                        <path fill="currentColor" fill-rule="evenodd" d="M12 1.25a4.75 4.75 0 1 0 0 9.5a4.75 4.75 0 0 0 0-9.5M8.75 6a3.25 3.25 0 1 1 6.5 0a3.25 3.25 0 0 1-6.5 0M12 12.25c-2.313 0-4.445.526-6.024 1.414C4.42 14.54 3.25 15.866 3.25 17.5v.102c-.001 1.162-.002 2.62 1.277 3.662c.629.512 1.51.877 2.7 1.117c1.192.242 2.747.369 4.773.369s3.58-.127 4.774-.369c1.19-.24 2.07-.605 2.7-1.117c1.279-1.042 1.277-2.5 1.276-3.662V17.5c0-1.634-1.17-2.96-2.725-3.836c-1.58-.888-3.711-1.414-6.025-1.414M4.75 17.5c0-.851.622-1.775 1.961-2.528c1.316-.74 3.184-1.222 5.29-1.222c2.104 0 3.972.482 5.288 1.222c1.34.753 1.961 1.677 1.961 2.528c0 1.308-.04 2.044-.724 2.6c-.37.302-.99.597-2.05.811c-1.057.214-2.502.339-4.476.339s-3.42-.125-4.476-.339c-1.06-.214-1.68-.509-2.05-.81c-.684-.557-.724-1.293-.724-2.601" clip-rule="evenodd"/></svg>                                       <span>User</span>
                                   </div>
                                   {/* <div>
                                       <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="feather feather-chevron-right"><polyline points="9 18 15 12 9 6"></polyline></svg>
                                   </div> */}
                               </Link>
                           </li>
                           <li className={`menu ${location.pathname === "/admin/alert" ? "active" : ""}`}>
                               <Link to="/admin/alert" className="dropdown-toggle">
                                   <div className="">
                                       <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24"><g fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2"><path stroke-dasharray="64" stroke-dashoffset="64" d="M12 3l9 17h-18l9 -17Z"><animate fill="freeze" attributeName="stroke-dashoffset" dur="0.6s" values="64;0"/></path><path stroke-dasharray="6" stroke-dashoffset="6" d="M12 10v4"><animate fill="freeze" attributeName="stroke-dashoffset" begin="0.6s" dur="0.2s" values="6;0"/><animate attributeName="stroke-width" begin="1.8s" dur="3s" keyTimes="0;0.1;0.2;0.3;1" repeatCount="indefinite" values="2;3;3;2;2"/></path><path stroke-dasharray="2" stroke-dashoffset="2" d="M12 17v0.01"><animate fill="freeze" attributeName="stroke-dashoffset" begin="0.8s" dur="0.2s" values="2;0"/><animate attributeName="stroke-width" begin="2.1s" dur="3s" keyTimes="0;0.1;0.2;0.3;1" repeatCount="indefinite" values="2;3;3;2;2"/></path></g></svg>                                       <span>Alert</span>
                                   </div>
                                   {/* <div>
                                       <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="feather feather-chevron-right"><polyline points="9 18 15 12 9 6"></polyline></svg>
                                   </div> */}
                               </Link>
                           </li>
                           <li className={`menu ${location.pathname === "/admin/contact" ? "active" : ""}`}>
                               <Link to="/admin/contact" className="dropdown-toggle">
                                   <div className="">
                                       <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="feather feather-zap"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>
                                       <span>Contacts & Quick Link</span>
                                   </div>
                                   {/* <div>
                                       <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="feather feather-chevron-right"><polyline points="9 18 15 12 9 6"></polyline></svg>
                                   </div> */}
                               </Link>
                           </li>
                           <li className={`menu ${location.pathname === "/admin/franchise" ? "active" : ""}`}>
                               <Link to="/admin/franchise" className="dropdown-toggle">
                                   <div className="">
                                     <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24"><path fill="currentColor" d="M22 3H2c-1.09.04-1.96.91-2 2v14c.04 1.09.91 1.96 2 2h20c1.09-.04 1.96-.91 2-2V5a2.074 2.074 0 0 0-2-2m0 16H2V5h20zm-8-2v-1.25c0-1.66-3.34-2.5-5-2.5s-5 .84-5 2.5V17zM9 7a2.5 2.5 0 0 0-2.5 2.5A2.5 2.5 0 0 0 9 12a2.5 2.5 0 0 0 2.5-2.5A2.5 2.5 0 0 0 9 7m5 0v1h6V7zm0 2v1h6V9zm0 2v1h4v-1z"/></svg>                                       <span>Franchisee Details</span>
                                   </div>
                                   {/* <div>
                                       <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="feather feather-chevron-right"><polyline points="9 18 15 12 9 6"></polyline></svg>
                                   </div> */}
                               </Link>
                           </li>
                           <li className={`menu ${location.pathname === "/admin/cmr_ndc_details" ? "active" : ""}`}>
                               <Link to="/admin/cmr_ndc_details" className="dropdown-toggle">
                                   <div className="">
                                     <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24"><path fill="currentColor" d="M3.5 20V3h1v16h16v1zm3.885-3.5V9.192h2V16.5zm4.5 0V4.192h2V16.5zm4.5 0v-3.308h2V16.5z"/></svg>                                       <span>CMR NDC Details</span>
                                   </div>
                                   {/* <div>
                                       <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="feather feather-chevron-right"><polyline points="9 18 15 12 9 6"></polyline></svg>
                                   </div> */}
                               </Link>
                           </li>
                           <li className={`menu ${location.pathname === "/admin/adminKnowledgeCenter" ? "active" : ""}`}>
                               <Link to="/admin/adminKnowledgeCenter" className="dropdown-toggle">
                                   <div className="">
                                     <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24"><path fill="currentColor" d="M15.102 16.162a8 8 0 1 1 1.06-1.06l4.618 4.618a.75.75 0 1 1-1.06 1.06zM16.5 10a6.5 6.5 0 1 0-13 0a6.5 6.5 0 0 0 13 0M10 9a.75.75 0 0 1 .75.75v3.5a.75.75 0 0 1-1.5 0v-3.5A.75.75 0 0 1 10 9m0-1.5a1 1 0 1 0 0-2a1 1 0 0 0 0 2"/></svg>                                       <span>Knowledge Center</span>
                                   </div>
                                   {/* <div>
                                       <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="feather feather-chevron-right"><polyline points="9 18 15 12 9 6"></polyline></svg>
                                   </div> */}
                               </Link>
                           </li>
                       </ul>

                   </nav>
               </div>
           </>
  )
}

export default adminSidebar

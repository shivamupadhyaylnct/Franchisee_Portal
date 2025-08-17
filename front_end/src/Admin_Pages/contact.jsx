import React from 'react'
import { useNavigate } from 'react-router-dom';

function contact(){
        const navigate = useNavigate();
        const handleNavClick = (e, value) => {
            e.preventDefault();
            navigate(value);
        };
    return(
        <>
                {/* <!--  BEGIN CONTENT AREA  --> */}
        <div id="content" className="main-content">
            <div className="layout-px-spacing1">

                <div className="middle-content container-xxl p-0">
                    <div id="tabsSimple" className="col-xl-12 col-12 layout-spacing mt-3">
                        <div className="statbox widget box box-shadow">
                            <div className="widget-header">
                                <div className="row">
                                    <div className="col-xl-12 col-md-12 col-sm-12 col-12">
                                        <h5 className="p-3">Contact and Quick Links</h5>
                                    </div>
                                </div>
                            </div>
                            <div className="widget-content widget-content-area px-3">

                                <div className="simple-pill">
                                    
                                    <ul className="nav nav-pills mb-3" id="pills-tab" role="tablist">
                                        <li className="nav-item" role="presentation">
                                            <button className="nav-link active" id="pills-home-icon-tab" data-bs-toggle="pill" data-bs-target="#pills-home-icon" type="button" role="tab" aria-controls="pills-home-icon" aria-selected="true">
                                                <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" className="feather feather-home"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"></path><polyline points="9 22 9 12 15 12 15 22"></polyline></svg>
                                               RBM Contacts
                                            </button>
                                        </li>
                                        <li className="nav-item" role="presentation">
                                            <button className="nav-link" id="pills-profile-icon-tab" data-bs-toggle="pill" data-bs-target="#pills-home-icon" type="button" role="tab" aria-controls="pills-home-icon" aria-selected="false">
                                                <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" className="feather feather-user"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>
                                                RCM Contacts
                                            </button>
                                        </li>
                                        <li className="nav-item" role="presentation">
                                            <button className="nav-link" id="pills-profile-icon-tab" data-bs-toggle="pill" data-bs-target="#pills-quick-icon" type="button" role="tab" aria-controls="pills-quick-icon" aria-selected="false">
                                                <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" className="feather feather-zap"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>
                                                Quick Links
                                            </button>
                                        </li>
                                       
                                    </ul>
                                    <div className="tab-content" id="pills-tabContent">
                                        <div className="tab-pane fade show active" id="pills-home-icon" role="tabpanel" aria-labelledby="pills-home-icon-tab" tabindex="0">
                                          
                                           
                                                <div className="row">
                                                    <div className="d-flex justify-content-end gap-2  mb-3">
                                                        <a href="/admin/dashboard" 
                                                            className="btn btn-primary"  
                                                            data-bs-toggle="modal" 
                                                            data-bs-target=""
                                                            onClick={(e) => handleNavClick(e, "/admin/dashboard")}>
                                                            <i className="fa fa-arrow-left me-2"></i> Back
                                                        </a>
                                                        <button className="btn btn-primary"  data-bs-toggle="modal" data-bs-target="#adduser"><i className="fa fa-add me-2"></i> Add Contact</button>
                                                    </div>
                                                   
                                                    <div className="col-xl-12 col-lg-12 col-sm-12  layout-spacing">
                                                        <div className="statbox widget box box-shadow">
                                                            <div className="widget-content widget-content-area">
                                                                <table id="html5-extension" className="table dt-table-hover" style={{width:"100%"}}>
                                                                    <thead>
                                                                        <tr className="table-secondary">
                    
                                                                            <th scope="col">User Name</th>
                                                                            <th scope="col">Contact</th>
                                                                            <th className="text-center dt-no-sorting">Action</th>
                                                                        </tr>
                                                                    </thead>
                                                                    <tbody>
                                                                        <tr>
                                                                           <td><span>Admin</span></td>
                                                                            <td><span>+91 95867 45852</span></td>
                                                                            <td className="text-center">
                                                                                <i className="fa fa-edit me-2"></i><i className="fa fa-trash me-2 text-danger"></i>
                                                                            </td>
                                                                        </tr>
                                                                        <tr>
                                                                            <td><span>Admin</span></td>
                                                                            <td><span>+91 95867 45852</span></td>
                                                                             <td className="text-center">
                                                                                 <i className="fa fa-edit me-2"></i><i className="fa fa-trash me-2 text-danger"></i>
                                                                             </td>
                                                                         </tr>
                                                                         <tr>
                                                                            <td><span>Admin</span></td>
                                                                            <td><span>+91 95867 45852</span></td>
                                                                             <td className="text-center">
                                                                                 <i className="fa fa-edit me-2"></i><i className="fa fa-trash me-2 text-danger"></i>
                                                                             </td>
                                                                         </tr>
                                                                         <tr>
                                                                            <td><span>Admin</span></td>
                                                                            <td><span>+91 95867 45852</span></td>
                                                                             <td className="text-center">
                                                                                <i className="fa fa-edit me-2"></i><i className="fa fa-trash me-2 text-danger"></i>
                                                                             </td>
                                                                         </tr>
                                                                         <tr>
                                                                            <td><span>Admin</span></td>
                                                                            <td><span>+91 95867 45852</span></td>
                                                                             <td className="text-center">
                                                                                 <i className="fa fa-edit me-2"></i><i className="fa fa-trash me-2 text-danger"></i>
                                                                             </td>
                                                                         </tr>
                                                                        
                    
                                                                    </tbody>
                                                                </table>
                                                            </div>
                                                        </div>
                                                    </div>
                                        </div>
                                        </div>
                                        
                                        <div className="tab-pane fade" id="pills-quick-icon" role="tabpanel" aria-labelledby="pills-quick-icon-tab" tabindex="0">
                                            <div className="d-flex align-items-center justify-content-end mb-3">
                                                      <a href="/admin/dashboard" 
                                                            className="btn btn-primary"  
                                                            data-bs-toggle="modal" 
                                                            data-bs-target=""
                                                            onClick={(e) => handleNavClick(e, "/admin/dashboard")}>
                                                            <i className="fa fa-arrow-left me-2"></i> Back
                                                        </a>
                                                <button className="btn btn-primary"  data-bs-toggle="modal" data-bs-target="#addlink"><i className="fa fa-add me-2"></i> Add Link</button>
                                            </div> 
                                            <div className="row">
                                               
                                               
                                                <div className="col-xl-12 col-lg-12 col-sm-12  layout-spacing">
                                                    <div className="statbox widget box box-shadow">
                                                        <div className="widget-content widget-content-area p-3">
                                                            <table  className="table" style={{width:"100%"}}>
                                                                <thead>
                                                                    <tr className="table-secondary">
                
                                                                        <th scope="col">Title</th>
                                                                        <th scope="col">Link</th>
                                                                        <th className="text-center dt-no-sorting">Action</th>
                                                                    </tr>
                                                                </thead>
                                                                <tbody>
                                                                    <tr>
                                                                       <td><span>Support</span></td>
                                                                        <td><span><a href="support.html" target="_blank">https://bixware.app/abfrlfranchiseportal.bixware.app/admin/support.html</a></span></td>
                                                                        <td className="text-center">
                                                                            <i className="fa fa-edit me-2" data-bs-toggle="modal" data-bs-target="#editlink"></i><i className="fa fa-trash me-2 text-danger"></i>
                                                                        </td>
                                                                    </tr>
                                                                    <tr>
                                                                        <td><span>Knowledge Center</span></td>
                                                                        <td><span><a href="knowledge.html" target="_blank">https://bixware.app/abfrlfranchiseportal.bixware.app/admin/knowledge.html</a></span></td>
                                                                         <td className="text-center">
                                                                             <i className="fa fa-edit me-2" data-bs-toggle="modal" data-bs-target="#editlink"></i><i className="fa fa-trash me-2 text-danger"></i>
                                                                         </td>
                                                                     </tr>
                                                                </tbody>
                                                            </table>
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
        </div>
        {/* <!--  END CONTENT AREA  --> */}
        </>
    )
}
export default contact;
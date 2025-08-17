import React from 'react'
import style1 from '../../src/assets/img/grid-blog-style-9.jpg';
import style2 from '../../src/assets/img/alert.jpg';
import style3 from '../../src/assets/img/contact.jpg';
import style4 from '../../src/assets/img/franchise.jpg';
import style5 from '../../src/assets/img/CMR_NDC_Details.jpg'
import style6 from '../../src/assets/img/grid-blog-style-8.jpg'
import { Link } from 'react-router-dom';



function adminDashboard() {

  return (
     <>
             {/* <!--  BEGIN CONTENT AREA  --> */}
        <div id="content" className="main-content">
            <div className="layout-px-spacing1">

                <div className="middle-content container-xxl p-0">
                    <div className="card mt-3">
                        <div className="card-body p-3">
                          
                            <div className="row mb-2">
                                <h5>Admin</h5> 

                                    <div className="col-lg-3 mb-3">
                                        <Link to="/admin/user" className="card" >
                                            <img src={style1} className="card-img-top" alt="..." />
                                            <div className="card-footer p-3">
                                                <div className="row d-flex justify-content-between align-items-center flex-nowrap">
                                                    <div className="col">
                                                        <h5 className="card-title mb-0 fs-17">Users</h5>
                                                    </div>
                                                    <div className="col-auto text-end">
                                                        <button className="btn btn-secondary _effect--ripple waves-effect waves-light d-flex align-items-center gap-2 px-3">
                                                            <span>View</span>
                                                            <i className="fas fa-arrow-right" aria-hidden="true" style={{ fontSize: '16px' }}></i>
                                                        </button>
                                                    </div>
                                                </div>
                                            </div>
                                        </Link>
                                    </div>
                                    
 
                                    <div className="col-lg-3 mb-3">
                                        <Link to="/admin/alert" className="card" >
                                            <img src={style2} className="card-img-top" alt="..." />
                                            <div className="card-footer p-3">
                                                <div className="row d-flex justify-content-between align-items-center flex-nowrap">
                                                    <div className="col">
                                                        <h5 className="card-title mb-0 fs-17">Alert</h5>
                                                    </div>
                                                    <div className="col-auto text-end">
                                                        <button className="btn btn-secondary _effect--ripple waves-effect waves-light d-flex align-items-center gap-2 px-3">
                                                            <span>View</span>
                                                            <i className="fas fa-arrow-right" aria-hidden="true" style={{ fontSize: '16px' }}></i>
                                                        </button>
                                                    </div>
                                                </div>
                                            </div>
                                        </Link>
                                    </div>

                                    <div className="col-lg-3 mb-3">
                                        <Link to="/admin/contact" className="card">
                                            <img src={style3} className="card-img-top" alt="..." />
                                            <div className="card-footer p-3">
                                                <div className="row d-flex justify-content-between align-items-center flex-nowrap">
                                                    <div className="col">
                                                        <h5 className="card-title mb-0 fs-17">Contacts & Quick Links</h5>
                                                    </div>
                                                    <div className="col-auto text-end">
                                                        <button className="btn btn-secondary _effect--ripple waves-effect waves-light d-flex align-items-center gap-2 px-3">
                                                            <span>View</span>
                                                            <i className="fas fa-arrow-right" aria-hidden="true" style={{ fontSize: '16px' }}></i>
                                                        </button>
                                                    </div>
                                                </div>
                                            </div>
                                        </Link>
                                    </div>

                                    <div className="col-lg-3 mb-3">
                                        <Link to="/admin/franchise" className="card">
                                            <img src={style4} className="card-img-top" alt="..." />
                                            <div className="card-footer p-3">
                                                <div className="row d-flex justify-content-between align-items-center flex-nowrap">
                                                    <div className="col">
                                                        <h5 className="card-title mb-0 fs-17">Franchise Details</h5>
                                                    </div>
                                                    <div className="col-auto text-end">
                                                        <button className="btn btn-secondary _effect--ripple waves-effect waves-light d-flex align-items-center gap-2 px-3">
                                                            <span>View</span>
                                                            <i className="fas fa-arrow-right" aria-hidden="true" style={{ fontSize: '16px' }}></i>
                                                        </button>
                                                    </div>
                                                </div>
                                            </div>
                                        </Link>
                                    </div>

                                      <div className="col-lg-3 mb-3">
                                        <Link to="/admin/cmr_ndc_details" className="card">
                                            <img src={style5} className="card-img-top" alt="..." />
                                            <div className="card-footer p-3">
                                                <div className="row d-flex justify-content-between align-items-center flex-nowrap">
                                                    <div className="col">
                                                        <h5 className="card-title mb-0 fs-17">CMR NDC Details</h5>
                                                    </div>
                                                    <div className="col-auto text-end">
                                                        <button className="btn btn-secondary _effect--ripple waves-effect waves-light d-flex align-items-center gap-2 px-3">
                                                            <span>View</span>
                                                            <i className="fas fa-arrow-right" aria-hidden="true" style={{ fontSize: '16px' }}></i>
                                                        </button>
                                                    </div>
                                                </div>
                                            </div>
                                        </Link>
                                    </div>


                                     <div className="col-lg-3 mb-3">
                                        <Link to="/admin/adminKnowledgeCenter" className="card">
                                            <img src={style6} className="card-img-top" alt="..." />
                                            <div className="card-footer">
                                                <div className="row d-flex justify-content-between align-items-center flex-nowrap">
                                                    <div className="col">
                                                        <h5 className="card-title mb-0 fs-17">Knowledge Center</h5>
                                                    </div>
                                                    <div className="col-auto text-end">
                                                        <button className="btn btn-secondary _effect--ripple waves-effect waves-light d-flex align-items-center gap-2 px-3">
                                                            <span>View</span>
                                                            <i className="fas fa-arrow-right" aria-hidden="true" style={{ fontSize: '16px' }}></i>
                                                        </button>
                                                    </div>
                                                </div>
                                            </div>
                                        </Link>
                                    </div>

                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        {/* <!--  END CONTENT AREA  --> */}
     </>
    // <>
    // <h1>Dashboard called</h1>
    // </>
  )
}

export default adminDashboard

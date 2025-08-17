import React from "react";
import { Link } from "react-router-dom";

function adminKnowledgeCenter() {
  return (
      <div id="content" className="main-content">
        <div className="layout-px-spacing1">
          <div className="middle-content container-fluid px-5">
           <div className="card mt-4">
            <div className="card-body" >
                <div className="d-flex align-items-center justify-content-between pb-5">
                  <h4>Knowledge Center</h4>
                  <div className="d-flex gap-2">
                    <Link to="/admin/dashboard">
                       <button className="btn btn-primary">
                        <i className="fa fa-arrow-left me-2"></i> Back
                       </button>
                    </Link>
                     
                  </div>
                </div>

               <div className="faq container">
                <div className="faq-layouting layout-spacing">
                  <div className="kb-widget-section">
                    <div className="row justify-content-center">

      {/* General module */}
                      <div className="col-12 col-sm-6 col-md-4 col-lg-3">
                        <Link to="/admin/adminKnowledgeCenter/general">
                          <div className="card">
                            <div className="card-body" >
                              <div className="card-icon mb-4">
                                <svg
                                  xmlns="http://www.w3.org/2000/svg"
                                  width="24"
                                  height="24"
                                  viewBox="0 0 24 24"
                                  fill="none"
                                  stroke="currentColor"
                                  stroke-width="2"
                                  stroke-linecap="round"
                                  stroke-linejoin="round"
                                  className="feather feather-airplay"
                                >
                                  <path d="M5 17H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2h-1"></path>
                                  <polygon points="12 15 17 21 7 21 12 15"></polygon>
                                </svg>
                              </div>
                              <h5 className="card-title mb-0">General</h5>
                            </div>
                          </div>
                        </Link>
                      </div>
      {/* Sop Module */}
                      <div className="col-12 col-sm-6 col-md-4 col-lg-3">
                        <Link to="/admin/adminKnowledgeCenter/sop">
                           <div className="card">
                            <div className="card-body">
                              <div className="card-icon mb-4">
                                <svg
                                  xmlns="http://www.w3.org/2000/svg"
                                  width="24"
                                  height="24"
                                  viewBox="0 0 24 24"
                                  fill="none"
                                  stroke="currentColor"
                                  stroke-width="2"
                                  stroke-linecap="round"
                                  stroke-linejoin="round"
                                  className="feather feather-user"
                                >
                                  <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
                                  <circle cx="12" cy="7" r="4"></circle>
                                </svg>
                              </div>
                              <h5 className="card-title mb-0">SOP</h5>
                            </div>
                          </div>
                        </Link>
                      </div>
      {/* Training Module */}
                      <div className="col-12 col-sm-6 col-md-4 col-lg-3">
                        <Link to="/admin/adminKnowledgeCenter/trainingModule">
                          <div className="card">
                          <div className="card-body" >
                            <div className="card-icon mb-4">
                              <svg
                                xmlns="http://www.w3.org/2000/svg"
                                width="24"
                                height="24"
                                viewBox="0 0 24 24"
                                fill="none"
                                stroke="currentColor"
                                stroke-width="2"
                                stroke-linecap="round"
                                stroke-linejoin="round"
                                className="feather feather-package"
                              >
                                <line
                                  x1="16.5"
                                  y1="9.4"
                                  x2="7.5"
                                  y2="4.21"
                                ></line>
                                <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"></path>
                                <polyline points="3.27 6.96 12 12.01 20.73 6.96"></polyline>
                                <line x1="12" y1="22.08" x2="12" y2="12"></line>
                              </svg>
                            </div>
                            <h5 className="card-title mb-0">Training Modules</h5>
                          </div>
                        </div>
                        </Link>
                      </div>
      {/* Franchise Helpbooks */}
                      <div className="col-12 col-sm-6 col-md-4 col-lg-3">
                        <Link to="/admin/adminKnowledgeCenter/franchiseeHelpbook">
                          <div className="card">
                          <div className="card-body" >
                            <div className="card-icon mb-4">
                              <svg
                                xmlns="http://www.w3.org/2000/svg"
                                width="24"
                                height="24"
                                viewBox="0 0 24 24"
                                fill="none"
                                stroke="currentColor"
                                stroke-width="2"
                                stroke-linecap="round"
                                stroke-linejoin="round"
                                className="feather feather-dollar-sign"
                              >
                                <line x1="12" y1="1" x2="12" y2="23"></line>
                                <path d="M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"></path>
                              </svg>
                            </div>
                            <h5 className="card-title mb-0"> Franchise Helpbooks </h5>
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
          </div>
        </div>
      </div>

  );
}

export default adminKnowledgeCenter;

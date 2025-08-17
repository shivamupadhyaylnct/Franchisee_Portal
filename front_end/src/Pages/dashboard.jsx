import React, { useEffect, useState } from 'react';
import Swal from "sweetalert2";
import style1 from '../../src/assets/img/grid-blog-style-1.jpg';
import style2 from '../../src/assets/img/grid-blog-style-2.jpg';
import style5 from '../../src/assets/img/grid-blog-style-5.jpg';
import style7 from '../../src/assets/img/grid-blog-style-7.jpg';
import style8 from '../../src/assets/img/grid-blog-style-8.jpg';
import { Link } from "react-router-dom";
import axios from 'axios';
import { baseURL } from '../base';
import { config } from '../config';

function Dashboard() {
    const [alerts, setAlerts] = useState([]);

    //===================== ( Alert Message )==================================

    // useEffect(() => {
    //     const fetchAlerts = async () => {
    //         try {
    //             const response = await axios.post(`${baseURL}${config.getallalerts}`, {
    //                 alertNames: [
    //                     "Agreement Expiration Notification",
    //                     "Stock Block and Payment Hold Alerts",
    //                     "Invoice Submission Reminder",
    //                     "Generic Message Alert"
    //                 ]
    //             });

    //             if (response.data.code === 200 && response.data.status === 'Success') {
    //                 const validAlerts = response.data.data.filter(alert => alert.isExpire === 1);
    //                 setAlerts(validAlerts);

    //   // fetching one time Welcome StockBlock Alert

    //                 const stockBlockAlert = validAlerts.find(
    //                     (alert) => alert.alertName === "Stock Block and Payment Hold Alerts"
    //                 );

    //                 if (stockBlockAlert && !sessionStorage.getItem("loginAlertShown")) {
    //                     Swal.fire({
    //                     title: "Welcome!",
    //                     text: stockBlockAlert.alertMessage,
    //                     icon: "warning",
    //                     confirmButtonText: "OK"
    //                     });

    //                     sessionStorage.setItem("loginAlertShown", "true");
    //                 }
    //             }
    //         } catch (error) {
    //             console.error('Failed to fetch alerts:', error);
    //         }
    //     };
    //     fetchAlerts();
    // }, []);

    // useEffect(() => {
    // const fetchAlerts = async () => {
    //     try {
    //         const response = await axios.post(`${baseURL}${config.getallalerts}`, {
    //             alertNames: [
    //                 "Agreement Expiration Notification",
    //                 "Stock Block and Payment Hold Alerts",
    //                 "Invoice Submission Reminder",
    //                 "Generic Message Alert"
    //             ]
    //         });
    //          console.log("API Response:", response.data); // Log response
    //         if (response.data.code === 200 && response.data.status === 'Success') {
    //             let validAlerts = response.data.data.filter(alert => alert.isExpire === 1);

    //             // Handle Generic Message Alert
    //             const genericAlerts = validAlerts.filter(a => a.alertName === "Generic Message Alert");

    //             if (genericAlerts.length > 0) {
    //                 const latestGeneric = genericAlerts.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))[0];
    //                 validAlerts = validAlerts.filter(a => a.alertName !== "Generic Message Alert");
    //                 if (latestGeneric.isVisible === 1) {
    //                     validAlerts.push(latestGeneric);
    //                 }
    //             }

    //             setAlerts(validAlerts);

    //             // === Welcome StockBlock Alert ===
    //             const stockBlockAlert = validAlerts.find(
    //                 (alert) => alert.alertName === "Stock Block and Payment Hold Alerts"
    //             );

    //             if (stockBlockAlert && !sessionStorage.getItem("loginAlertShown")) {
    //                 Swal.fire({
    //                     title: "Welcome!",
    //                     text: stockBlockAlert.alertMessage,
    //                     icon: "warning",
    //                     confirmButtonText: "OK"
    //                 });

    //                 sessionStorage.setItem("loginAlertShown", "true");
    //             }
    //         }
    //     } catch (error) {
    //         console.error('Failed to fetch alerts:', error);
    //     }
    // };

    // fetchAlerts();
    // }, []);

    useEffect(() => {
    const fetchAlerts = async () => {
        try {
            const response = await axios.post(`${baseURL}${config.getallalerts}`, {
                alertNames: [
                    "Agreement Expiration Notification",
                    "Stock Block and Payment Hold Alerts",
                    "Invoice Submission Reminder",
                    "Generic Message Alert"
                ]
            });
            console.log("API Response:", response.data);
            if (response.data.code === 200 && response.data.status === 'Success') {
                let validAlerts = response.data.data.filter(alert => alert.isExpire === 1);
                console.log("Valid Alerts:", validAlerts);
                const genericAlerts = validAlerts.filter(a => a.alertName === "Generic Message Alert");
                if (genericAlerts.length > 0) {
                    const latestGeneric = genericAlerts[0]; // API already sorts by createdAt
                    console.log("Latest Generic Alert:", latestGeneric);
                    validAlerts = validAlerts.filter(a => a.alertName !== "Generic Message Alert");
                     console.log("hgfhg",latestGeneric.isVisible);
                    if (latestGeneric.isVisible === true){
                        validAlerts.push(latestGeneric);
                    }
                }
                console.log("Final Alerts:", validAlerts);
                setAlerts([...validAlerts]); // Ensure new array for re-render
                const stockBlockAlert = validAlerts.find(
                    (alert) => alert.alertName === "Stock Block and Payment Hold Alerts"
                );
                if (stockBlockAlert && !sessionStorage.getItem("loginAlertShown")) {
                    Swal.fire({
                        title: "Welcome!",
                        text: stockBlockAlert.alertMessage,
                        icon: "warning",
                        confirmButtonText: "OK"
                    });
                    sessionStorage.setItem("loginAlertShown", "true");
                }
            }
        } catch (error) {
            console.error('Failed to fetch alerts:', error);
        }
    };
    fetchAlerts();
}, []);


    //=========================================================================

    useEffect(() => {
        document.body.classList.add("layout-boxed");
        document.body.classList.add("enable-secondaryNav");
    }, []);


    return (
        <>
            {/* <!--  BEGIN CONTENT AREA  --> */}
            <div id="content" className="main-content">
                {/* Alert   Notification  */}
                <div className="marquee-wrapper" style={{ width: '100%', overflow: 'hidden', backgroundColor: '#f9f9f9', padding: '10px ', }}>
                    <div className="marquee-track" style={{ display: 'flex', width: 'max-content', whiteSpace: 'nowrap', animation: 'scroll-left 50s linear infinite', }} >
                     {/* filter out that stock block alert first then map it */}
                 {
                   alerts.filter((alert) => alert.alertName !== "Stock Block and Payment Hold Alerts")
                         .map((alert, index) => {
                            let bgColor = '';
                            let textColor = '';
                            switch (alert.alertName) {
                                case 'Agreement Expiration Notification':
                                    bgColor = '#fce8cd';
                                    textColor = '#e2a03f';
                                    break;
                                case 'Invoice Submission Reminder':
                                    bgColor = '#ede7f6';
                                    textColor = '#805dca';
                                    break;
                                case 'Generic Message Alert':
                                    bgColor = '#d3f4e5';
                                    textColor = '#00B264';
                                    break;
                                default:
                                    bgColor = '#e0e0e0';
                                    textColor = '#000';
                            }
                            return (
                                <span key={index} style={{ display: 'inline-block', backgroundColor: bgColor, color: textColor, padding: '8px 16px', borderRadius: '8px', marginRight: '10px', fontSize: '20px', whiteSpace: 'nowrap', }} >
                                    {alert.alertMessage}
                                </span>
                            );
                        })}
                    </div>
                    <style>
                        {`
                            @keyframes scroll-left {
                                0% {
                                transform: translateX(100vw);
                                }
                                100% {
                                transform: translateX(-100%);
                                }
                            }
                            .marquee-wrapper:hover {
                                animation-play-state: paused;
                            }
                        `}
                    </style>
                </div>
                {/* Alert   Notification  End */}


                <div className="layout-px-spacing1">
                    <div className="middle-content container-xxl p-0">
                        {/* <!--  BEGIN BREADCRUMBS  --> */}
                        <div className="secondary-nav d-lg-none">
                            <div className="breadcrumbs-container" data-page-heading="Analytics">
                                <header className="header navbar navbar-expand-sm mb-3">
                                    <a className="btn-toggle sidebarCollapse" data-placement="bottom">
                                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="feather feather-menu">
                                            <line x1="3" y1="12" x2="21" y2="12"></line>
                                            <line x1="3" y1="6" x2="21" y2="6"></line><line x1="3" y1="18" x2="21" y2="18"></line>
                                        </svg>
                                    </a>
                                </header>
                            </div>
                        </div>
                        {/* <!--  END BREADCRUMBS  --> */}

                        <div className="row layout-top-spacing">
                            {/* <!--Left sidebar--> */}
               
                            <div className="col-lg-12">
                                <div className="row">

                                    <div className="col-lg-3 mb-3">
                                        <Link to="/user/store" className="card">
                                            <img src={style2} className="card-img-top" alt="..." />
                                            <div className="card-footer">
                                                <div className="row d-flex justify-content-between align-items-center flex-nowrap">
                                                    <div className="col">
                                                        <h5 className="card-title mb-0 fs-17">Stores</h5>
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
                                        <Link to="/user/statements/commission" className="card">
                                            <img src={style1} className="card-img-top" alt="..." />
                                            <div className="card-footer">
                                                <div className="row d-flex justify-content-between align-items-center flex-nowrap">
                                                    <div className="col">
                                                        <h5 className="card-title mb-0 fs-17">Statements</h5>
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
                                        <Link to="/user/declaration" className="card">
                                            <img src={style5} className="card-img-top" alt="..." />
                                            <div className="card-footer">
                                                <div className="row d-flex justify-content-between align-items-center flex-nowrap">
                                                    <div className="col">
                                                        <h5 className="card-title mb-0 fs-17">Declarations</h5>
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
                                        <Link to="/user/support" className="card" >
                                            <img src={style7} className="card-img-top" alt="..." />
                                            <div className="card-footer">
                                                <div className="row d-flex justify-content-between align-items-center flex-nowrap">
                                                    <div className="col">
                                                        <h5 className="card-title mb-0 fs-17">Support</h5>
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
                                        <Link to="/user/knowledgecenter" className="card" >
                                            <img src={style8} className="card-img-top" alt="..." />
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
                            {/* <!--content--> */}
                        </div>
                    </div>
                </div>
            </div>
            {/* <!--  END CONTENT AREA  --> */}

        </>
    )
}

export default Dashboard
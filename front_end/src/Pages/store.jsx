import React, { useEffect, useState } from "react";
import logo from '../../src/assets/img/logo.jpg';
import cover from '../../src/assets/img/cover.jpg';
import cover1 from '../../src/assets/img/cover1.jpg';
import cover2 from '../../src/assets/img/cover2.jpg';
import axios from 'axios';
import { toast } from "react-toastify";
import 'react-toastify/dist/ReactToastify.css';
import { baseURL } from "../base";
import { config } from "../config";

function Store() {
    const user = localStorage.getItem("user_details");
    const userDetails = JSON.parse(user)

    const [storeDetails, setStoreDetails] = useState({})
    const [storeCodes, setStoreCodes] = useState([])
    const [selectedStoreCode, setSelectedStoreCode] = useState("")
    const [activeStoreCode, setActiveStoreCode] = useState(null);
    const vendorCodes = userDetails.map(u => u.UserName);
    // console.log("Vendor codes are", vendorCodes);

    const [vendorCodeWithName, setVendorCodeWithName] = useState([]);
    // console.log("All vender code fetched are=> ", vendorCodeWithName);

    const [selectedVendor, setSelectedVendor] = useState('');
	const [selectedFranchiseName, setSelectedFranchiseName] = useState("");
    const handleStoreCodeChange = (value) => {
        setSelectedStoreCode(value);
        setActiveStoreCode(value);
        getStoreDetails(value)
    };

    const handleVendorCodeChange = (event) => {
        setSelectedVendor(event.target.value)
    };

    const formatSapDate = (dateString) => {
        if (dateString == undefined) return '';
        if (dateString == '') return '';
        if (dateString.length != 8) return '';
        const year = dateString.substring(0, 4);
        const month = dateString.substring(4, 6);
        const day = dateString.substring(6, 8);
        return `${day}-${month}-${year}`;
    };

    useEffect(()=>{
        const fetchVendorFranchisee = async () => {
        try {
			const vendorCodes = userDetails.map(u => u.UserName);
            // console.log("vendorCodes =:",userDetails)

            /*if(userDetails.length === 1 && userDetails[0]?.UserType === "USER"){
                console.log("vendor Login is :",userDetails[0]?.UserName)
                setVendorCodeWithName([{
                    vendorCode: userDetails[0]?.UserName
                }]);
                return; // skip API call
            }*/
            const res = await axios.post(`${baseURL}${config.getVendorWithFranchisee}`,{vendorCodes});
            if (res.data.code === 200) {
                setVendorCodeWithName(res.data.data);
                // console.log("vendor with name",res.data.data)
            }
            } catch (err) {
            console.error("Error fetching vendor:", err);
            } 
        };
        fetchVendorFranchisee();
    },[selectedFranchiseName])

    async function getStoreCodes() {
        const response = await axios.post(`${baseURL}${config.getallstoredetails}`, {
            storeUID: selectedVendor
        });
        try {
            if (response.data.code === 201) {
                return response.data.all_store_details;
            }
        } catch (error) {
            console.error("Error fetching store codes:", error);
            toast.error("Error connecting to the server.");
            return null;
        }
    }

    async function getStoreDetails(value) {
        try {
            const response = await axios.post(`${baseURL}${config.getstoredetails}`, {
                storeUID: value
            });
            if (response.data.code === 404) {
                toast.error("User not found");

            } else if (response.data.code === 401) {
                toast.error("Incorrect Password");
            } else if (response.data.code === 201) {
                // console.log(response.data)
                setStoreDetails(response.data.store_details)
            }

            // console.log('Response:', response.data);

        } catch (error) {
            console.error('Error:', error);
        }
    }


    useEffect(() => {
        if (selectedVendor === "") {
            setSelectedVendor(vendorCodes[0])
        }
        if (selectedVendor) {
            (async () => {
                const newData = await getStoreCodes();
                if (newData) {
                    setStoreCodes(newData.ALL_STORE);
                    const firstCode = newData.ALL_STORE[0].LEGACY_CODE;
                    setSelectedStoreCode(firstCode);
                    setActiveStoreCode(firstCode);
                    getStoreDetails(firstCode);
                }
            })();
        }
    }, [selectedVendor]);


    return (
        <>
            {/* <!--  BEGIN CONTENT AREA  --> */}
            <div id="content" className="main-content">
                <div className="layout-px-spacing1">

                    <div className="middle-content container-xxl p-0 mt-3">
                        <div className="row layout-top-spacing">
                            <div id="tabsSimple" className="col-xl-12 col-12 mb-2">
                                <div className="statbox widget box box-shadow">
                                    <div className="widget-header p-3">
                                        <div className="d-flex flex-wrap justify-content-between align-items-center">
                                            {/* Left Side - Title */}
                                            <h5 className="mb-2 mb-md-0">Store Details</h5>

                                            {/* Right Side - Label + Select */}
                                            {/* {console.log(vendorCodeWithName)} */}
                                            <div className="d-flex flex-wrap align-items-center">
                                                <label htmlFor="selectvendor" className="me-2 mb-1">Vendor Code</label>
                                                <select
                                                    name="selectvendor"
                                                    id="selectvendor"
                                                    className="form-select"
                                                    style={{ width: '350px' }}
                                                    value={selectedVendor}
                                                    onChange={handleVendorCodeChange}
                                                >
                                                    <option value="" disabled> Select Vendor Code </option>
                                                        {vendorCodeWithName.map((option) => (
                                                            <option key={option.vendorCode} value={option.vendorCode}>
                                                                {option.vendorCode}  {option.vendorName ? ` - ${option.vendorName}` : ""}
                                                            </option>
                                                        ))}
                                                </select>
                                                
                                            </div>
                                        </div>
                                    </div>
                                    <div className="widget-content widget-content-area pt-0 pb-0">
                                        <div className="row">
                                            <div className="col-lg-10">
                                                <div className="vertical-pill">

                                                    <div className="d-flex justify-content-between align-items-start">
                                                        <div className="nav flex-column nav-pills me-3 col-lg-2" id="v-pills-tab" role="tablist" aria-orientation="vertical" style={{ height: '390px' }}>
                                                            {
                                                                storeCodes.map((store) => {
                                                                    const isActive = store.LEGACY_CODE === activeStoreCode;
                                                                    return (
                                                                        <button
                                                                            key={store.LEGACY_CODE}
                                                                            className={`nav-link ${isActive ? "active" : ""}`}
                                                                            onClick={() => handleStoreCodeChange(store?.LEGACY_CODE)}
                                                                            id="v-pills-home-tab"
                                                                            data-bs-toggle="pill"
                                                                            data-bs-target="#v-pills-home"
                                                                            type="button"
                                                                            role="tab"
                                                                            aria-controls="v-pills-home"
                                                                            aria-selected="true">{store?.LEGACY_CODE.slice(-4)}
                                                                        </button>
                                                                    )
                                                                })
                                                            }

                                                        </div>
                                                        <div className="tab-content col-lg-10" id="v-pills-tabContent">
                                                            <div className="tab-pane fade show active" id="v-pills-home" role="tabpanel" aria-labelledby="v-pills-home-tab" tabIndex="0">
                                                                <div className="row invoice layout-spacing">
                                                                    <div className="col-xl-12 col-lg-12 col-md-12 col-sm-12 col-12">

                                                                        <div className="doc-container">

                                                                            <div className="row">

                                                                                <div className="col-xl-12">

                                                                                    <div className="invoice-container">
                                                                                        <div className="invoice-inbox">

                                                                                            <div id="ct" className="">

                                                                                                <div className="invoice-00001">
                                                                                                    <div className="content-section">

                                                                                                        <div className="inv--head-section inv--detail-section px-2 py-2 mb-2">
                                                                                                            <div className="row">
                                                                                                                <div className="col-sm-6 col-12 mr-auto">
                                                                                                                    <div className="d-flex">
                                                                                                                        <img className="company-logo" src={logo} alt="company" />
                                                                                                                        <h3 className="in-heading align-self-center"></h3>
                                                                                                                    </div>
                                                                                                                    {/* {console.log("Details are = ",storeDetails.WA_FRNCHSE )} */}
                                                                                                                    <p className="inv-street-addr mt-3">{storeDetails?.STORE?.NAME}</p>
                                                                                                                    <p className="inv-email-address">{storeDetails?.STORE?.SMTP_ADDR}</p>
                                                                                                                    <p className="inv-email-address">{storeDetails?.STORE?.HOUSE_NUM1}</p>
                                                                                                                    <p className="inv-email-address">{storeDetails?.STORE?.TEL_NUMBER}</p>
                                                                                                                </div>

                                                                                                                <div className="col-sm-6 text-sm-end">
                                                                                                                    <p className="inv-list-number mt-sm-3 pb-sm-2 mt-4"><span className="inv-title">Store Code : </span> <span className="inv-number">#{activeStoreCode?activeStoreCode.slice(-4):""}</span></p>
                                                                                                                    <p className="inv-created-date mt-sm-5 mt-3"><span className="inv-title">Store Type : </span> <span className="inv-date">{storeDetails?.STORE?.STR_TYP}</span></p>
                                                                                                                    <p className="inv-due-date"><span className="inv-title">Start Date : </span> <span className="inv-date">{formatSapDate(storeDetails?.STORE?.STR_OPN_DATE)}</span></p>
                                                                                                                </div>
                                                                                                            </div>

                                                                                                        </div>

                                                                                                        <div className="inv--detail-section inv--customer-detail-section px-2 py-2">

                                                                                                            <div className="row">

                                                                                                                <div className="col-xl-8 col-lg-7 col-md-6 col-sm-4 align-self-center">
                                                                                                                    <h6 className="inv-title">Address</h6>
                                                                                                                </div>

                                                                                                                {/* <div className="col-xl-4 col-lg-5 col-md-6 col-sm-8 align-self-center order-sm-0 order-1 text-sm-end mt-sm-0 mt-5">
                                                                                                                    <h6 className="inv-title">Address</h6>
                                                                                                                </div> */}

                                                                                                                <div className="col-xl-8 col-lg-7 col-md-6 col-sm-4">
                                                                                                                    <div className="inv-details">
                                                                                                                        {/* <p><span className="label"><b>PAN No.:</b></span> <span className="value">{storeDetails?.WA_FRNCHSE?.J_1IPANNO}</span></p>
                                                                                                                        <p><span className="label"><b>GST No.:</b></span> <span className="value">{storeDetails?.WA_FRNCHSE?.SERVICETAX}</span></p>
                                                                                                                        <p><span className="label"><b>Bank Name:</b></span> <span className="value">{storeDetails?.WA_FRNCHSE?.BANKA}</span></p>
                                                                                                                        <p><span className="label"><b>Bank Account No:</b></span> <span className="value">{storeDetails?.WA_FRNCHSE?.BANKN} </span></p>
                                                                                                                        <p><span className="label mb-3"><b>IFSC Code:</b></span> <span className="value mb-3"> {storeDetails?.WA_FRNCHSE?.IFSC}</span></p> */}

                                                                                                                        <p className="inv-email-address">{storeDetails?.STORE?.STREET}</p>
                                                                                                                        <p className="inv-email-address">{storeDetails?.STORE?.CITY1}</p>
                                                                                                                        <p className="inv-email-address">{storeDetails?.STORE?.BEZEI}</p>
                                                                                                                        <p className="inv-email-address">{storeDetails?.STORE?.LANDX}</p>
                                                                                                                        <p className="inv-email-address">{storeDetails?.STORE?.POST_CODE1}</p>
                                                                                                                    </div>
                                                                                                                </div>

                                                                                                                {/* <div className="col-xl-4 col-lg-5 col-md-6 col-sm-8 col-12 order-sm-0 order-1 text-sm-end">
                                                                                                                    <p className="inv-customer-name">King style</p>
                                                                                                                    <p className="inv-street-addr">{storeDetails?.WA_FRNCHSE?.STREET}</p>
                                                                                                                    <p className="inv-street-addr">{storeDetails?.WA_FRNCHSE?.CITY1}</p>
                                                                                                                    <p className="inv-street-addr">{storeDetails?.WA_FRNCHSE?.BEZEI}</p>
                                                                                                                    <p className="inv-email-address">{storeDetails?.WA_FRNCHSE?.LANDX}</p>
                                                                                                                    <p className="inv-email-address">{storeDetails?.WA_FRNCHSE?.POST_CODE1}</p>
                                                                                                                </div> */}

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
                                                            <div className="tab-pane fade" id="v-pills-profile" role="tabpanel" aria-labelledby="v-pills-profile-tab" tabIndex="0">
                                                                <div className="row invoice layout-spacing">
                                                                    <div className="col-xl-12 col-lg-12 col-md-12 col-sm-12 col-12">

                                                                        <div className="doc-container">

                                                                            <div className="row">

                                                                                <div className="col-xl-12">

                                                                                    <div className="invoice-container">
                                                                                        <div className="invoice-inbox">

                                                                                            <div id="ct" className="">

                                                                                                <div className="invoice-00001">
                                                                                                    <div className="content-section">

                                                                                                        <div className="inv--head-section inv--detail-section px-2 py-2 mb-2">

                                                                                                            <div className="row">

                                                                                                                <div className="col-sm-6 col-12 mr-auto">
                                                                                                                    <div className="d-flex">
                                                                                                                        <img className="company-logo" src={logo} alt="company" />
                                                                                                                        <h3 className="in-heading align-self-center"></h3>
                                                                                                                    </div>
                                                                                                                    <p className="inv-street-addr mt-3">Aditya Birla Fashion and Retails Ltd</p>
                                                                                                                    <p className="inv-email-address">kingstyle@gmail.com</p>
                                                                                                                    <p className="inv-email-address">+1 (530) 555-12121</p>
                                                                                                                </div>

                                                                                                                <div className="col-sm-6 text-sm-end">
                                                                                                                    <p className="inv-list-number mt-sm-3 pb-sm-2 mt-4"><span className="inv-title">Store Code : </span> <span className="inv-number">#1200427</span></p>
                                                                                                                    <p className="inv-created-date mt-sm-5 mt-3"><span className="inv-title">Store Type : </span> <span className="inv-date">FOFO</span></p>
                                                                                                                    <p className="inv-due-date"><span className="inv-title">Start Date : </span> <span className="inv-date">26 Mar 2022</span></p>
                                                                                                                </div>
                                                                                                            </div>

                                                                                                        </div>

                                                                                                        <div className="inv--detail-section inv--customer-detail-section px-2 py-2">

                                                                                                            <div className="row">

                                                                                                                <div className="col-xl-8 col-lg-7 col-md-6 col-sm-4 align-self-center">
                                                                                                                    <h6 className="inv-title">Other Details</h6>
                                                                                                                </div>

                                                                                                                <div className="col-xl-4 col-lg-5 col-md-6 col-sm-8 align-self-center order-sm-0 order-1 text-sm-end mt-sm-0 mt-5">
                                                                                                                    <h6 className="inv-title">Address</h6>
                                                                                                                </div>

                                                                                                                <div className="col-xl-8 col-lg-7 col-md-6 col-sm-4">
                                                                                                                    <div className="inv-details">
                                                                                                                        <p><span className="label"><b>PAN No.:</b></span> <span className="value">ACAPS4473R</span></p>
                                                                                                                        <p><span className="label"><b>GST No.:</b></span> <span className="value">27ACAPS4473R1ZT</span></p>
                                                                                                                        <p><span className="label"><b>Bank Name:</b></span> <span className="value">HDFC BANK LIMITED</span></p>
                                                                                                                        <p><span className="label"><b>Bank Account No:</b></span> <span className="value">01462790000089 </span></p>
                                                                                                                        <p><span className="label"><b>IFSC Code:</b></span> <span className="value"> HDFC0000146</span></p>
                                                                                                                    </div>
                                                                                                                </div>

                                                                                                                <div className="col-xl-4 col-lg-5 col-md-6 col-sm-8 col-12 order-sm-0 order-1 text-sm-end">
                                                                                                                    <p className="inv-customer-name">King style</p>
                                                                                                                    <p className="inv-street-addr">Thane</p>
                                                                                                                    <p className="inv-street-addr">Mumbai</p>
                                                                                                                    <p className="inv-email-address">India</p>
                                                                                                                    <p className="inv-email-address">400602</p>
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
                                                            </div>

                                                            <div className="tab-pane fade" id="v-pills-contact" role="tabpanel" aria-labelledby="v-pills-contact-tab" tabIndex="0">
                                                                <div className="row invoice layout-spacing">
                                                                    <div className="col-xl-12 col-lg-12 col-md-12 col-sm-12 col-12">

                                                                        <div className="doc-container">

                                                                            <div className="row">

                                                                                <div className="col-xl-12">

                                                                                    <div className="invoice-container">
                                                                                        <div className="invoice-inbox">

                                                                                            <div id="ct" className="">

                                                                                                <div className="invoice-00001">
                                                                                                    <div className="content-section">

                                                                                                        <div className="inv--head-section inv--detail-section px-2 py-2 mb-2">

                                                                                                            <div className="row">

                                                                                                                <div className="col-sm-6 col-12 mr-auto">
                                                                                                                    <div className="d-flex">
                                                                                                                        <img className="company-logo" src={logo} alt="company" />
                                                                                                                        <h3 className="in-heading align-self-center"></h3>
                                                                                                                    </div>
                                                                                                                    <p className="inv-street-addr mt-3">Aditya Birla Fashion and Retails Ltd</p>
                                                                                                                    <p className="inv-email-address">kingstyle@gmail.com</p>
                                                                                                                    <p className="inv-email-address">+1 (530) 555-12121</p>
                                                                                                                </div>

                                                                                                                <div className="col-sm-6 text-sm-end">
                                                                                                                    <p className="inv-list-number mt-sm-3 pb-sm-2 mt-4"><span className="inv-title">Store Code : </span> <span className="inv-number">#1202392</span></p>
                                                                                                                    <p className="inv-created-date mt-sm-5 mt-3"><span className="inv-title">Store Type : </span> <span className="inv-date">FOFO</span></p>
                                                                                                                    <p className="inv-due-date"><span className="inv-title">Start Date : </span> <span className="inv-date">26 Mar 2022</span></p>
                                                                                                                </div>
                                                                                                            </div>

                                                                                                        </div>

                                                                                                        <div className="inv--detail-section inv--customer-detail-section px-2 py-2">

                                                                                                            <div className="row">

                                                                                                                <div className="col-xl-8 col-lg-7 col-md-6 col-sm-4 align-self-center">
                                                                                                                    <h6 className="inv-title">Other Details</h6>
                                                                                                                </div>

                                                                                                                <div className="col-xl-4 col-lg-5 col-md-6 col-sm-8 align-self-center order-sm-0 order-1 text-sm-end mt-sm-0 mt-5">
                                                                                                                    <h6 className="inv-title">Address</h6>
                                                                                                                </div>

                                                                                                                <div className="col-xl-8 col-lg-7 col-md-6 col-sm-4">
                                                                                                                    <div className="inv-details">
                                                                                                                        <p><span className="label"><b>PAN No.:</b></span> <span className="value">ACAPS4473R</span></p>
                                                                                                                        <p><span className="label"><b>GST No.:</b></span> <span className="value">27ACAPS4473R1ZT</span></p>
                                                                                                                        <p><span className="label"><b>Bank Name:</b></span> <span className="value">HDFC BANK LIMITED</span></p>
                                                                                                                        <p><span className="label"><b>Bank Account No:</b></span> <span className="value">01462790000089 </span></p>
                                                                                                                        <p><span className="label"><b>IFSC Code:</b></span> <span className="value"> HDFC0000146</span></p>
                                                                                                                    </div>
                                                                                                                </div>

                                                                                                                <div className="col-xl-4 col-lg-5 col-md-6 col-sm-8 col-12 order-sm-0 order-1 text-sm-end">
                                                                                                                    <p className="inv-customer-name">King style</p>
                                                                                                                    <p className="inv-street-addr">Thane</p>
                                                                                                                    <p className="inv-street-addr">Mumbai</p>
                                                                                                                    <p className="inv-email-address">India</p>
                                                                                                                    <p className="inv-email-address">400602</p>
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
                                                            </div>
                                                        </div>
                                                    </div>

                                                </div>
                                            </div>
                                            {/* <!--left side content ends--> */}
                                            {/* <!--right side slider--> */}
                                            <div className="col-lg-2" id="storesright">

                                                <div className="invoice-actions-btn p-1">

                                                    <div className="invoice-action-btn">

                                                        <div id="carouselExampleSlidesOnly" className="carousel slide" data-bs-ride="carousel">
                                                            <div className="carousel-inner">
                                                                <div className="carousel-item active">
                                                                    <img className="d-block w-100" src={cover2} alt="First slide" />
                                                                </div>
                                                                <div className="carousel-item">
                                                                    <img className="d-block w-100" src={cover1} alt="Second slide" />
                                                                </div>
                                                                <div className="carousel-item">
                                                                    <img className="d-block w-100" src={cover} alt="Third slide" />
                                                                </div>
                                                            </div>
                                                        </div>

                                                    </div>

                                                </div>

                                            </div>
                                            {/* <!--right side ends--> */}
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

export default Store
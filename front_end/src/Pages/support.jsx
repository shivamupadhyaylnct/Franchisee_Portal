import axios from "axios";
import { useEffect, useRef, useState } from "react";
import { toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import { baseURL, base, Azure_Upload_URL } from "../base";
import { config } from "../config";
import { Link } from "react-router-dom";
import { Button } from "@mui/material";
import { BlobServiceClient } from '@azure/storage-blob';

function Support() {
    const user = localStorage.getItem("user_details");
    const userDetails = JSON.parse(user);
    const [isLoading, setIsLoading] = useState(false);
    
    const [vendorCodeWithName, setVendorCodeWithName] = useState([]);
    const [selectedFranchiseName, setSelectedFranchiseName] = useState("");
    const [selectedEmail, setSelectedEmail] = useState('');

    const [storeCodes, setStoreCodes] = useState([]);
    const [selectedStoreCode, setSelectedStoreCode] = useState("");

    const region = ["East", "West", "North", "South"];
    const [selectedRegion, setSelectedRegion] = useState("");

    const queryType = [
        "Rental Payment",
        "Commission Payment",
        "Incentive Payment",
        "TAX issue - TDS",
        "TAX issue - GST",
        "Agreement Related Query",
        "Stores Tender Reconciliation",
        "Ledger Reconciliation",
        "Other",
    ];

    const [selectedQueryType, setSelectedQueryType] = useState("");
    const [caseTitle,setCaseTitle] = useState('')
    const [queryComments,setQueryComments] = useState('')
    const [phoneNumber,setPhoneNumber] = useState('')

    //===================================(File Handling)=================================
    const allowedFileType=[
        'application/pdf', // PDF
        'text/plain', // TXT
        'text/csv', // CSV
        'application/msword', // Word (doc)
    ];
    const maxFileSize=20*1024*1024;

    const fileInputRef = useRef(null);
    const [file, setFile] = useState(null);
    const [error,setError] = useState('')

    const handleFileChange = (e) => {
        const selectedFile = e.target.files[0];
        setError('');

        if(selectedFile){
            if(!allowedFileType.includes(selectedFile.type)){
                setError('Invalid file type. Please upload a PDF, TXT, CSV or Doc File only.')
                setFile(null);
                fileInputRef.current.value = '';
                return;
            }
           
        }
        if(selectedFile.size > maxFileSize){
            setError("File maximum size is 20MB limit")
            setFile(null)
            fileInputRef.current.value = '';
            return;
        }
        setFile(selectedFile);
    };


    //===============================================

        useEffect(()=>{
        const fetchVendorFranchisee = async () => {
            try {
                const vendorCodes = userDetails.map(u => u.UserName);
                const res = await axios.post(`${baseURL}${config.getVendorWithFranchisee}`,{vendorCodes});
                if (res.data.code === 200) {
                    setVendorCodeWithName(res.data.data);
                    console.log("vendor info",res.data.data)
                    // Find and set the email based on the selected vendor code
                    const selectedVendor = userDetails.find(u => u.UserName === selectedFranchiseName);
                    if (selectedVendor) {
                    setSelectedEmail(selectedVendor.EmailId);
                    }
                }
            } catch (err) {
            console.error("Error fetching vendor:", err);
            } 
        };
        fetchVendorFranchisee();
    },[selectedFranchiseName])



    useEffect(() => {
        if (!selectedFranchiseName) return;

        const fetchStoreCodes = async () => {
            try {
                // console.log("Sending storeUID is =:", selectedFranchiseName);
                const response = await axios.post( `${baseURL}${config.getallstoredetails}`, { storeUID: selectedFranchiseName } );
                if (response.data.code === 201 && response.data.all_store_details?.ALL_STORE?.length) {
                    const storeList = response.data.all_store_details.ALL_STORE;
                    setStoreCodes(storeList);
                    setSelectedStoreCode(storeList[0].LEGACY_CODE);
                } else {
                    console.warn("Unexpected response code or empty list:", response.data);
                    setStoreCodes([]);
                    setSelectedStoreCode("");
                }
            } catch (error) {
                console.error("Error fetching store codes:", error.message);
                toast.error("Error connecting to the server.");
                setStoreCodes([]);
                setSelectedStoreCode("");
            }
        };

        fetchStoreCodes();
    }, [selectedFranchiseName]);


    //=================================================================

    const resetForm = () => {
        setSelectedQueryType("");
        setSelectedFranchiseName("");
        setSelectedEmail("");
        setSelectedStoreCode("");
        setPhoneNumber("");
        setSelectedRegion("");
        setCaseTitle("");
        setQueryComments("");
        setFile(null);
        if (fileInputRef.current) {
        fileInputRef.current.value = null; // Reset file input
        }
    };

    // Common Handle
    const handleChange = (event) => {
        const { name, value } = event.target;

            if (name === "selectedStoreCode") {
            setSelectedStoreCode(value);
            } else if (name === "selectedQueryType") {
            setSelectedQueryType(value);
            } else if (name === "phoneNumber") {
            setPhoneNumber(value);
            } else if (name === "selectedRegion") {
            setSelectedRegion(value);
            } else if (name === "caseTitle") {
            setCaseTitle(value);
            } else if (name === "queryComments") {
            setQueryComments(value);
            } else if (name === "selectedFranchiseName") {
            setSelectedFranchiseName(value);
            const selectedVendor = userDetails.find((u) => u.UserName === value);
                    if (selectedVendor) {
                    setSelectedEmail(selectedVendor.EmailId);
                    } else {
                    setSelectedEmail(""); // Clear email if no vendor found
                    }
            }
        };

    const handleSubmit = async () => {
        const VendorCode = 'ABFRL';
        console.groupCollapsed("Query Entries")
        console.log("QueryType :", selectedQueryType);
        console.log("VendorCode :", VendorCode);
        console.log("Name :", selectedFranchiseName);
        console.log("Email :",selectedEmail);
        console.log("StoreCode :", selectedStoreCode);
        console.log("Phone :", phoneNumber);
        console.log("Region :", selectedRegion);
        console.log("CaseTitle :", caseTitle);
        console.log("QueryComments :", queryComments);
        console.log("file :", file ? file.name : "No file selected")
        console.groupEnd()

        // Frontend Security Files
        // const sasToken = process.env.REACT_APP_SAS_TOKEN;
        // const storageAccountName = process.env.REACT_APP_STORAGE_NAME;
        // const containerName = process.env.REACT_APP_CONTAINER_NAME;
        const sasToken = '8AsWfol+VU1u4D6YMKRzPrJBwG1//up9Egka9e+qdimj53XpvfdWh4R+gHUm9RLWbZKryi+BMkHlPoYt3kd+Vw==';
        const storageAccountName = 'abfrlsonatastorage';
        const containerName = 'pscdata';
        
        if (!sasToken || !storageAccountName || !containerName) {
            toast.error("Missing Azure Blob Storage configuration. Please contact support.");
            return;
            }

        
        try {
            if (
                !selectedQueryType || !VendorCode || !selectedFranchiseName ||
                !selectedEmail || !selectedStoreCode || !phoneNumber ||
                !selectedRegion || !caseTitle || !queryComments
            ) {
                if (!selectedQueryType) {
                toast.warning("Please Provide Query Type");
                } else if (!selectedFranchiseName) {
                toast.warning("Please provide Franchisee Name");
                } else if (!selectedEmail) {
                toast.warning("Email id dosen't Fetched");
                } else if (!storeCodes) {
                toast.warning("Please provide Store Code Details");
                } else if (!phoneNumber) {
                toast.warning("Please provide Phone Number");
                } else if (!selectedRegion) {
                toast.warning("Please Provide Region");
                } else if (!caseTitle) {
                toast.warning("Please provide Case Title");
                } else if (!queryComments) {
                toast.warning("Please provide Query Comments");
                } return;
            } else {
            
                setIsLoading(true);
                //=============== Upload file to Azure Blob============
                //creates a client to interact with your Azure storage
                const blobServiceClient = new BlobServiceClient(
                    `https://${storageAccountName}.blob.core.windows.net?${sasToken}`
                );
                
                // Create container in the Azure to use
                 let blobUrl = "";
                 const containerClient = blobServiceClient.getContainerClient(containerName);

                 if(file){
                        //  const uniqueFileName = `${Date.now()}_${file.name}`; // for unique name
                        //object handler to upload file
                        const blockBlobClient = containerClient.getBlockBlobClient(file.name); 
        
                        //Azure Uploading with saftly Check in try-catch
                        try {
                            await blockBlobClient.uploadData(file, {
                                blobHTTPHeaders: { blobContentType: file.type },
                            });
                            //generate url to upload the file
                            blobUrl = `https://${storageAccountName}.blob.core.windows.net/${containerName}/${file.name}`;
                        } catch (err) {
                                toast.error("File upload to Azure failed. Please try again.");
                                console.error("Azure Blob upload failed:", err);
                                return;
                            }

                 }
                 
                

                // Prepare Payload
                const payload = {
                    QueryType: selectedQueryType,
                    VendorCode: VendorCode,
                    Name: selectedFranchiseName,
                    Email: selectedEmail,
                    StoreCode: selectedStoreCode.replace(/^0+/, ""),
                    Phone: phoneNumber,
                    Region: selectedRegion,
                    CaseTitle: caseTitle,
                    QueryComments: queryComments,
                    // Attachmentlink:'',
                    Attachmentlink: file ? blobUrl : ""
                };

                // API request
                const response = await axios.post( `${Azure_Upload_URL}/PscCaseCreation`, payload );
                if (response?.data?.code === 201) {
                    toast.success( `Query submitted successfully with file "${file.name}"` );
                    resetForm(); // Reset form including file input

                } else {
                    toast.error("Data upload failed");
                }
            }
        } 
        catch (error) {
            console.error( "Data upload failed:", error.response?.data?.message || error.message );
            toast.error(error.response?.data?.message || error.message);
        } finally {
        setIsLoading(false);
        }
    };

    return (
        <>
        {/* <!--  BEGIN CONTENT AREA  --> */}
        <div id="content" className="main-content">
            <div className="layout-px-spacing1">
            <div className="middle-content container-xxl p-5">
                <div id="tabsSimple" className="col-xl-12 col-12 layout-spacing mt-3" >
                <div className="statbox widget bg-white">
                    {/* ================= (heading And Back Button Pill) ================== */}
                    <div className="card m-4">
                        <div className="card-body">
                            <div className="d-flex align-items-center justify-content-between">
                                <h3 className="p-1">Support</h3>
                                <div className="d-flex gap-2">
                                    <Link to="/user/dashboard" className="btn btn-primary">
                                    <i className="fa fa-arrow-left me-2"></i> Back
                                    </Link>
                                </div>
                            </div>
                        </div>
                    </div>
                    {/* ======================================= */}

                    <div className="widget-content widget-content-area pt-0">
                    <div className="tab-content" id="pills-tabContent">
                        <div
                        id="pills-profile-icon"
                        role="tabpanel"
                        aria-labelledby="pills-profile-icon-tab"
                        tabIndex="0"
                        >
                        <div className="row p-3">
                            <div
                            className="form border rounded p-3"
                            style={{ border: "2px solid black" }}
                            >
                            <div className="row">
                                <div className="col-md-4 mb-3">
                                <div className="form-group">
                                    <label htmlFor="queryType">Query Type</label>
                                    <select
                                    name="selectedQueryType"
                                    id="queryType"
                                    value={selectedQueryType}
                                    className="form-select"
                                    onChange={handleChange}
                                    >
                                    <option value="" disabled> {" "} All..{" "} </option>
                                    {queryType.map((option) => (
                                        <option key={option} value={option}> {" "} {option}{" "} </option>
                                    ))}
                                    </select>
                                </div>
                                </div>

                                <div className="col-md-4 mb-3">
                                <div className="form-group">
                                    <label htmlFor="vendorCode">User Name</label>
                                    <select 
                                        name="selectedFranchiseName" 
                                        id="country" 
                                        className="form-select" 
                                        value={selectedFranchiseName}
                                        onChange={handleChange}>    
                                        <option value="" disabled> Select Vendor Code </option>
                                        {vendorCodeWithName.map((option) => (
                                            <option key={option.vendorCode} value={option.vendorCode}>
                                                {option.vendorCode}  {option.vendorName ? ` - ${option.vendorName}` : ""}
                                            </option>
                                        ))}
                                    </select>
                                    
                                </div>
                                </div>

                                <div className="col-md-4 mb-3">
                                <div className="form-group">
                                    <label htmlFor="email">Email ID</label>
                                <input
                                        name="email"
                                        id="email"
                                        style={{color:"black"}}
                                        type="text"
                                        className="form-control text-black bg-white"
                                        value={selectedEmail}
                                        readOnly
                                    />
                                </div>
                                </div>

                                <div className="col-md-4 mb-3">
                                <div className="form-group">
                                    <label htmlFor="address">Store Code</label>
                                    <select
                                        name="selectedStoreCode"
                                        id="country"
                                        className="form-select"
                                        value={selectedStoreCode}
                                        onChange={handleChange}
                                    >
                                    <option value="" disabled> Select Store Code </option>
                                    {storeCodes.map((option) => (
                                        <option key={option.LEGACY_CODE} value={option.LEGACY_CODE}> 
                                                {option.LEGACY_CODE.replace(/^0+/, "")} 
                                        </option>
                                    ))}
                                    </select>
                                </div>
                                </div>

                                <div className="col-md-4 mb-3">
                                <div className="form-group">
                                    <label htmlFor="phoneNumber" className="form-label" > Phone Number </label>
                                    <input 
                                        type="tel" 
                                        className="form-control"
                                        id="phoneNumber"
                                        name="phoneNumber"
                                        value={phoneNumber}
                                        placeholder="Enter phone number"
                                        onChange={handleChange}
                                    />
                                </div>
                                </div>

                                <div className="col-md-4 mb-3">
                                <div className="form-group">
                                    <label htmlFor="selectedRegion">Region</label>
                                        <select
                                            name="selectedRegion"
                                            id="selectedRegion"
                                            className="form-select"
                                            value={selectedRegion}
                                            onChange={handleChange}
                                        >
                                        <option value="" disabled> Select Region </option> 
                                        {region.map((option,index) => (
                                            <option key={index} value={option}> {option} </option>
                                            ))
                                            }
                                        </select>
                                </div>
                                </div>

                                <div className="col-md-4 mb-3">
                                <div className="form-group">
                                    <label htmlFor="caseTitle">Case Title</label>
                                    <input
                                        type="text"
                                        className="form-control text-black"
                                        id="caseTitle"
                                        name="caseTitle"
                                        value={caseTitle}
                                        placeholder="Enter Title For The Case"
                                        onChange={handleChange}
                                    />
                                </div>
                                </div>

                                <div className="col-md-4 mb-3">
                                <div className="form-group">
                                    <label htmlFor="queryComments">Query Comments</label>
                                    <textarea
                                        className="form-control text-black"
                                        id="queryComments"
                                        name="queryComments"
                                        rows="4"
                                        value={queryComments}
                                        placeholder="Enter your comments"
                                        onChange={handleChange}
                                    />
                                </div>
                                </div>

                                <div className="col-md-4 mt-2 mb-3">
                                <div className="form-group">
                                    <label htmlFor="location">Choose file </label>
                                    <br />
                                    <label htmlFor="file-upload" style={{ cursor: "pointer" }} >
                                        <Button variant="contained" component="span"> Choose File </Button>
                                    </label>
                                    <input
                                        id="file-upload"
                                        type="file"
                                        style={{ display: "none" }}
                                        onChange={handleFileChange}
                                        ref={fileInputRef}
                                    />
                                    <span> <b>{file ? file.name : 'No file chosen'}</b> </span>
                                    {error && (
                                       <p style={{ color: 'red', marginTop: '5px' }}>{error}</p>
                                    )}
                                </div>
                                </div>

                                <div className="col-md-12 d-flex justify-content-end mt-5 mb-3">
                                <div className="form-group ">
                                    <Button
                                        onClick={handleSubmit}
                                        variant="contained"
                                        color="primary"
                                        style={{ marginLeft: "1rem" }}
                                        disabled={isLoading || error}
                                    >
                                        Submit File
                                    </Button>
                                </div>
                                </div>

                            </div>
                            </div>
                        </div>
                        </div>
                        {/* ======================================= */}
                    </div>
                    </div>
                    {/* ==================================== */}
                </div>
                </div>
            </div>
            </div>
        </div>
        {/* <!--  END CONTENT AREA  --> */}
        </>
    )
}

export default Support;
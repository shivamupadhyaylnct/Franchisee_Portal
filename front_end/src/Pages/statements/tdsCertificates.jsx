import React, { useEffect, useRef, useState } from 'react'
import { Table } from 'smart-webcomponents-react/table';
import 'smart-webcomponents-react/source/styles/smart.default.css';
import { toast } from "react-toastify";
import 'react-toastify/dist/ReactToastify.css';
import axios from 'axios';
import { BeatLoader } from 'react-spinners';
import { baseURL, base } from '../../base';
import { config } from '../../config';

function tdsCertificates() {
    const tableRef = useRef();
    const user = localStorage.getItem("user_details");
    const userDetails = JSON.parse(user)

    const [vendorCodeWithName, setVendorCodeWithName] = useState([]);
    // console.log("All vender code fetched are=> ", vendorCodeWithName);

    const [selectedFranchiseName, setSelectedFranchiseName] = useState("");

    const [years, setYears] = useState([]);
    const [selectedYear, setSelectedYear] = useState("");
    const [tableData, setTableData] = useState([]);
    const [loading, setLoading] = useState(false);

 
        useEffect(()=>{
        const fetchVendorFranchisee = async () => {
            try {
                    const vendorCodes = userDetails.map(u => u.UserName);
                    // console.log("vendorCodes =:",userDetails)
                    
                    const res = await axios.post(`${baseURL}${config.getVendorWithFranchisee}`,{vendorCodes});
                    if (res.data.code === 200) {
                        setVendorCodeWithName(res.data.data);
                    }
                } catch (err) {
                    console.error("Error fetching vendor:", err);
                    } 
        };
        fetchVendorFranchisee();
    },[])

    useEffect(() => {
        const currentYear = new Date().getFullYear();
        const generatedYears = [];
        for (let year = currentYear; year >= 2010; year--) {
            generatedYears.push(year);
        }
        setYears(generatedYears);
    }, []);


    const handleChange = (event) => {
        const { name, value } = event.target;

        if (name === "selectedFranchiseName") {
            setSelectedFranchiseName(value);
            console.log("value is",value)
        } else {
            setSelectedYear(value);
        }
    };



    // const handleChangeTds = async () => {
    //     try {
    //         if (selectedFranchiseName == "") {
    //             toast.error("Please Select Franchise");
    //             return;
    //         }
    //         if (selectedYear == "") {
    //             toast.error("Please Provide Year");
    //             return;
    //         }
            
    //         setLoading(true);
    //         // Get franchise PANNO
    //             const franchise = userDetails.find(item => item.UserName === selectedFranchiseName);
    //              if (!franchise?.PANNO) {
    //                     setLoading(false);
    //                     toast.error("Franchise PAN number not found. Please try again.");
    //                     return;
    //              }
            
    //         // create payload 
    //             const payload = { year: selectedYear, PANNO: franchise.PANNO };
    //             console.log("Payload:",payload);

    //             const response = await axios.post(`${baseURL}${config.getallTdsDetails}`, payload);
    //             if (response.data.code === 200) {

    //                 if (response.data.files?.length > 0) {
    //                      const formattedData = response.data.files.map((fileName, index) => ({
    //                         sno: index + 1,
    //                         name: fileName,
    //                         Download: `<a href="${base}media/tds-certificates/${fileName}" target="_blank" 
    //                            rel="noopener noreferrer" download 
    //                            class="btn btn-sm btn-primary">Download</a>`,
    //                     }));
    //                     setTableData(formattedData);
    //                     if (tableRef.current) tableRef.current.dataSource = formattedData;
                        
    //                 } else if (response.data.code === 204) {
    //                     setTableData([]);
    //                     toast.info(`No TDS records found for ${selectedYear}.`);
    //                 } else if (response.data.code === 404) {
    //                     setTableData([]);
    //                     toast.error("TDS certificate folder not found on the server.");
    //                 } else if (response.data.code === 500) {
    //                         setTableData([]);
    //                         toast.error("Server error while reading TDS certificates. Please contact support.");
    //                 } else {
    //                         setTableData([]);
    //                         toast.error(`Unexpected response: ${response.data.message || "Unknown error"}`);
    //                     } 
    //             }

    //     } catch (error) {
    //         console.error("Error fetching TDS details:", error);
    //        if (error.response?.status === 500) {
    //             toast.error("Server crashed while processing your request.");
    //         } else if (error.code === "ERR_NETWORK") {
    //             toast.error("Network error — please check your internet connection.");
    //         } else {
    //             toast.error("Failed to fetch TDS details. Please try again.");
    //         }
    //     } finally {
    //     setLoading(false);
    //     }
    // };


      const handleChangeTds = async () => {
        try {
            if (selectedFranchiseName === "") {
                toast.error("Please Select Franchise");
                return;
            }
            if (selectedYear === "") {
                toast.error("Please Provide Year");
                return;
            }
            
            setLoading(true);
            // Get franchise PANNO
                const franchise = userDetails.find(item => item.UserName === selectedFranchiseName);
                 if (!franchise?.PANNO) {
                        setLoading(false);
                        toast.error("Franchise PAN number not found. Please try again.");
                        return;
                 }
            
            // create payload 
                const payload = { year: selectedYear, PANNO: franchise.PANNO };
                console.log("Payload:",payload);

                const response = await axios.post(`${baseURL}${config.getallTdsDetails}`, payload);
                if (response.data.code === 200) {
                    if (response.data.files?.length > 0) {
                        const formattedData = response.data.files.map((fileName, index) => ({
                        sno: index + 1,
                        name: fileName,
                        Download: `<a href="${base}media/tds-certificates/${fileName}" target="_blank" 
                            rel="noopener noreferrer" download 
                            class="btn btn-sm btn-primary">Download</a>`,
                        }));
                        setTableData(formattedData);
                        if (tableRef.current) tableRef.current.dataSource = formattedData;
                    }  
                } else if (response.data.code === 204) {
                    setTableData([]);
                    toast.info(`No TDS records found for ${selectedYear}.`);
                } else if (response.data.code === 404) {
                    setTableData([]);
                    toast.error("TDS certificate folder not found on the server.");
                } else if (response.data.code === 500) {
                        setTableData([]);
                        toast.error("Server error while reading TDS certificates. Please contact support.");
                } else {
                        setTableData([]);
                        toast.error(`Unexpected response: ${response.data.message || "Unknown error"}`);
                } 

        } catch (error) {
            console.error("Error fetching TDS details:", error);
           if (error.response?.status === 500) {
                toast.error("Server crashed while processing your request.");
            } else if (error.code === "ERR_NETWORK") {
                toast.error("Network error — please check your internet connection.");
            } else {
                toast.error("Failed to fetch TDS details. Please try again.");
            }
        } finally {
        setLoading(false);
        }
    };

    const appearance = {
        alternationStart: 0,
        alternationCount: 2,
    };

    const paging = true;
    const pageIndex = 0;
    const pageSize = 10;

    const columns = [
        {
            label: 'Serial No',
            dataField: 'sno',
            width: 100,
        },
        {
            label: 'File Name',
            dataField: 'name',
            dataType: 'string',
            width: 300,
            allowHtml: false
        },
        {
            label: 'Download',
            dataField: 'Download',
            dataType: 'string',
            width: 150,
            allowHtml: true,
        }
    ];


    return (
        <>
            {/* <!--  BEGIN CONTENT AREA  --> */}
            <div id="content" className="main-content">
                <div className="layout-px-spacing1">
                    <div className="middle-content container-xxl p-0">
                        <div className="card mt-3">
                            <div className="card-body">
                                <h5>TDS Certificates</h5>
                                <div className="row p-3">
                                    <div className="form">
                                        <div className="row">



                                            <div className="col-md-4 mb-3">
                                                <div className="form-group">
                                                    <label htmlFor="fullName"> Vendor Code </label>
                                                    <select name="selectedFranchiseName" 
                                                            id="franchise" 
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
                                                    <label>Year</label>
                                                    <select name="selectedStoreCode"
                                                        id="country" className="form-select"
                                                        value={selectedYear}
                                                        onChange={handleChange}>
                                                        <option value="">Select Year</option>
                                                        {years.map((year) => (
                                                            <option key={year} value={year}>
                                                                {year}
                                                            </option>
                                                        ))}
                                                    </select>
                                                </div>
                                            </div>

                                            <div className="col-md-12 mt-3">
                                                <div className="form-group text-start">
                                                    <button className="btn btn-secondary" onClick={handleChangeTds} >Download</button>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>

                        {/* ====================================== */}
                        {
                            tableData.length > 0 ? (
                                <>
                                    {loading ? (
                                        <>
                                            <div style={{ display: 'flex', justifyContent: 'center', marginTop: '4rem' }}>
                                                <BeatLoader color="#0257A7" height={4} width={100} loading={loading} />
                                            </div>
                                        </>
                                    ) : (
                                        <div className="card mt-3 ">
                                            <div className="card-body ">
                                                <div className="row ">
                                                    <div className="col-xl-12 col-lg-12 col-sm-12  layout-spacing ">
                                                        <div className="statbox widget box box-shadow">
                                                            <div className="widget-content widget-content-area">
                                                                <Table
                                                                    ref={tableRef}
                                                                    id="table"
                                                                    appearance={appearance}
                                                                    dataSource={tableData}
                                                                    paging={paging}
                                                                    pageIndex={pageIndex}
                                                                    pageSize={pageSize}
                                                                    columns={columns}
                                                                    freezeHeader={true}
                                                                    className="my-smart-table"
                                                                ></Table>
                                                            </div>
                                                        </div>
                                                    </div>

                                                </div>
                                            </div>
                                        </div>
                                    )

                                    }
                                </>
                            ) : (<div style={{ display: 'flex', justifyContent: 'center', marginTop: '4rem' }}>No Records Found</div>)
                        }

                        {/* =================================== */}
                    </div>

                </div>
            </div>


            {/* <!--  END CONTENT AREA  --> */}
        </>
    )
}

export default tdsCertificates

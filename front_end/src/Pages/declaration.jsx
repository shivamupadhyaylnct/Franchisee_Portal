import axios from 'axios';
import React, { useEffect, useRef, useState } from 'react'
import { Table } from 'smart-webcomponents-react/table';
import 'smart-webcomponents-react/source/styles/smart.default.css';
import { toast } from "react-toastify";
import 'react-toastify/dist/ReactToastify.css';
import { BeatLoader } from 'react-spinners';
import { baseURL, base } from '../base';
import { config } from '../config';
import { Link } from 'react-router-dom';

function Declaration() {
  const tableRef = useRef();
  const user = localStorage.getItem("user_details");
  const userDetails = JSON.parse(user)

  const [storeCodes, setStoreCodes] = useState([])
  const [selectedStoreCode, setSelectedStoreCode] = useState("")

  const [vendorCodeWithName, setVendorCodeWithName] = useState([]);
  // console.log("All vender code fetched are=> ", vendorCodeWithName);

  const [selectedFranchiseName, setSelectedFranchiseName] = useState("");

  const financialYear = ["2022-2023", "2023-2024", "2024-2025", "2025-2026"]
  const [selectedFinancialYear, setSelectedFinancialYear] = useState("");
  const financialQuarter = ["Q1", "Q2", "Q3", "Q4"]
  const [selectedFinancialQuarter, setSelectedFinancialQuarter] = useState("");
  const [ndcDetails, setNdcDetails] = useState([]);
  const [loading, setLoading] = useState(false);


  // Common Dropdown for Franchise Name, Financial year and financial quarter using name attribute
    const handleChange = (event) => {
      const { name, value } = event.target; //Destructring
      console.log(`selected franchisee name is ${selectedFranchiseName}`)
      
      if (name === 'selectedFranchiseName') {
        setSelectedFranchiseName(value);
      } else if (name === 'selectedFinancialYear') {
        setSelectedFinancialYear(value);
      } else if (name === 'selectedFinancialQuarter') {
        setSelectedFinancialQuarter(value);
      } else if (name === 'selectedStoreCode') {
        setSelectedStoreCode(value);
      }
    };

    useEffect(()=>{
      const fetchVendorFranchisee = async () => {
     try {
            const vendorCodes = userDetails.map(u => u.UserName);
            console.log("vendorCodes =:",userDetails)

            const res = await axios.post(`${baseURL}${config.getVendorWithFranchisee}`,{vendorCodes});
            if (res.data.code === 200) {
                setVendorCodeWithName(res.data.data);
            }
        } catch (err) {
          console.error("Error fetching vendor:", err);
          } 
      };
      fetchVendorFranchisee();
  },[selectedFranchiseName])


  async function getStoreCodes() {
    const response = await axios.post(`${baseURL}${config.getallstoredetails}`, {
      storeUID: selectedFranchiseName
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

  useEffect(() => {
    (async () => {
      const newData = await getStoreCodes();
      console.log("Fetched StoreCodes response:", newData);

      if (newData?.ALL_STORE) {
        setStoreCodes(newData.ALL_STORE);
        setSelectedStoreCode(newData.ALL_STORE[0].LEGACY_CODE);
      } else {
        setSelectedStoreCode(""); // fallback
      }
    })();
  }, [selectedFranchiseName])


  const dataExport = {
    view: true,
    viewStart: 0,
    viewEnd: 50
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
      label: 'Name Of File',
      dataField: 'name',
      dataType: 'string',
      width: 300,
    },
    {
      label: 'Download',
      dataField: 'fileUrl',  // use the raw URL here
      dataType: 'string',
      width: 150,
      formatFunction: (settings) => {
        settings.template = `
          <a href="${settings.value}" target="_blank" download class="btn btn-sm btn-primary">
            Download
          </a>
        `;
      }
    }
  ];

  const handleDownload = () => {
    const link = document.createElement("a");
    link.href = "/media/cmr/NDCFormat.doc"; // Adjust this path to your actual file location
    link.download = "NDCFormat.doc";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link); // cleanup
  };


  const handleSubmit = async () => {
    try {
      if (selectedFranchiseName == "") {
        toast.error("please Provide Franchise Name");
        return;
      }

      if (selectedStoreCode == "") {
        toast.error("please Provide Store Code");
        return;
      }


      else {
        setLoading(true);
        const storeCode = selectedStoreCode// "2023-2024" → "2024"
        const response = await axios.post(`${baseURL}${config.getCmrDetails}`, {
          year: selectedFinancialYear,
          quarter: selectedFinancialQuarter,
          storecode: storeCode
        });

          const { code, message, files } = response?.data;
          if (code === 204 || !files || files.length === 0) {
            toast.info(message || "No files found for selected store/quarter/year.");
            setNdcDetails([]);
            setLoading(false);
            return;
          }

        if (response.data && response.data.files) {
          // const baseURL = "http://192.168.2.173:8000/media/cmr/";

          const formattedData = response.data.files.map((file, index) => ({
            sno: index + 1,
            name: file,
            fileUrl: `${base}media/cmr/${file}`
          }));

          console.log("Formatted Files:", formattedData);
          setNdcDetails(formattedData);
          setTimeout(() => { setLoading(false); }, 1000);
          if (tableRef.current) {
            tableRef.current.dataSource = formattedData;
          }
  
        } else {
          toast.warn( "No files found for selected store/quarter/year.");
          setNdcDetails([]); // clear the table if nothing found
          setLoading(false);
        }
      }
    } catch (error) {
      console.error('Error is :', error.message);

    }
  };

  return (
    <>
      {/* <!--  BEGIN CONTENT AREA  --> */}
      <div id="content" className="main-content">
        <div className="layout-px-spacing1">

          <div className="middle-content container-xxl p-0">
            <div id="tabsSimple" className="col-xl-12 col-12 layout-spacing mt-3">
              <div className="statbox widget box box-shadow">
                <div className="widget-header">
                  <div className="d-flex align-items-center justify-content-between">
                        <h4 className="p-3" >Declarations</h4>
                        <div className="d-flex gap-2 m-3">
                            <Link to="/user/dashboard">
                                <button className="btn btn-primary">
                                    <i className="fa fa-arrow-left me-2"></i> Back
                                </button>
                            </Link>
                        </div>
                    </div>
                    </div>

                {/* ==================================== */}
                <div className="widget-content widget-content-area pt-0">
                  <div className="simple-pill">
                    <ul className="nav nav-pills mb-3" id="pills-tab" role="tablist">
                      <li className="nav-item" role="presentation">
                        <button className="nav-link active" id="pills-home-icon-tab" data-bs-toggle="pill" data-bs-target="#pills-home-icon" type="button" role="tab" aria-controls="pills-home-icon" aria-selected="true">
                          <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="feather feather-home"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"></path><polyline points="9 22 9 12 15 12 15 22"></polyline></svg>
                          NDC Format
                        </button>
                      </li>
                      <li className="nav-item" role="presentation">
                        <button className="nav-link" id="pills-profile-icon-tab" data-bs-toggle="pill" data-bs-target="#pills-profile-icon" type="button" role="tab" aria-controls="pills-profile-icon" aria-selected="false">
                          <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="feather feather-user"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>
                          CMR NDC Details
                        </button>
                      </li>
                    </ul>
                    <div className="tab-content" id="pills-tabContent">
                      {/* ======================================= */}

                      <div className="tab-pane fade show active" id="pills-home-icon" role="tabpanel" aria-labelledby="pills-home-icon-tab" tabIndex="0">
                        {/* <!-- <button className="btn btn-success btn-rounded">  <i className="fa fa-download me-2"></i>  Click here to Download the NDC Format</a></button> --> */}
                        <div className="row">

                          <div className="col-lg-6">

                            <div className="drag-area mt-3" onClick={handleDownload} style={{ cursor: "pointer" }}>
                              <div className="icon mt-3">
                                <i className="fa fa-cloud-download" aria-hidden="true"></i>
                              </div>
                              <center><h5 className="text-primary">Click here to Download NDC Format</h5></center>
                            </div>

                          </div>

                        </div>
                      </div>

                      {/* ======================================= */}

                      <div className="tab-pane fade" id="pills-profile-icon" role="tabpanel" aria-labelledby="pills-profile-icon-tab" tabIndex="0">
                        <div className="row p-3">
                          <div className="form border rounded p-3" style={{ border: "2px solid black" }}>
                            <div className="row">

                              <div className="col-md-6 mb-3">
                                <div className="form-group">
                                  <label htmlFor="fullName">Vendor Code  </label>

                                  <select name="selectedFranchiseName" 
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

                              <div className="col-md-6 mb-3">
                                <div className="form-group">
                                  <label htmlFor="address">Store Code</label>
                                  <select name="selectedStoreCode"
                                    id="country" className="form-select"
                                    value={selectedStoreCode}
                                    onChange={handleChange}
                                  >
                                    <option value="" disabled> Select Store Code </option>
                                    {
                                      storeCodes.map((option) => (
                                        <option key={option.LEGACY_CODE}
                                          value={option.LEGACY_CODE}>
                                          {option.LEGACY_CODE.slice(-4)}
                                        </option>
                                      ))
                                    }
                                  </select>
                                </div>
                              </div>

                              <div className="col-md-4 mb-3">
                                <div className="form-group">
                                  <label htmlFor="location">Financial Year</label>
                                  <select name="selectedFinancialYear" id="country" className="form-select" value={selectedFinancialYear}
                                    onChange={handleChange}>
                                    <option value="" disabled>All..</option>
                                    {financialYear.map((option) => (
                                      <option key={option} value={option}>{option}</option>
                                    ))}
                                  </select>
                                </div>
                              </div>

                              <div className="col-md-4 mb-3">
                                <div className="form-group">
                                  <label htmlFor="location">Financial Quarter</label>
                                  <select name="selectedFinancialQuarter" id="country" className="form-select" value={selectedFinancialQuarter}
                                    onChange={handleChange}>
                                    <option value="" disabled>ALL..</option>
                                    {financialQuarter.map((option) => (
                                      <option key={option} value={option}>{option}</option>
                                    ))}
                                  </select>
                                </div>
                              </div>

                              <div className="col-md-4 mt-3 mt-auto">
                                <div className="form-group text-end">
                                  <button className="btn btn-secondary" onClick={handleSubmit} >View</button>
                                </div>
                              </div>
                            </div>
                          </div>
                        </div>
                        {/* ======================================= */}

                        {
                          ndcDetails.length > 0 ? (
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
                                            <svg xmlns="http://www.w3.org/2000/svg" width="34" height="34" viewBox="0 0 24 24" style={{ cursor: "pointer" }}>
                                              <g fill="none" stroke="#0257a7" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.5" color="#0257a7">
                                                <path d="M10.294 14.016C10.248 13.024 9.571 13 8.651 13C7.235 13 7 13.338 7 14.667v1.666C7 17.662 7.235 18 8.651 18c.92 0 1.598-.024 1.643-1.016M21 13l-1.463 3.912c-.272.725-.407 1.088-.622 1.088s-.35-.363-.622-1.088L16.83 13m-2.109 0h-.972c-.389 0-.583 0-.736.063c-.522.216-.515.724-.515 1.187s-.007.97.515 1.187c.153.063.347.063.736.063c.388 0 .583 0 .736.063c.522.216.515.724.515 1.187s.007.97-.515 1.187c-.153.063-.348.063-.736.063h-1.06" />
                                                <path d="M15 22h-4.273c-3.26 0-4.892 0-6.024-.798a4.1 4.1 0 0 1-.855-.805C3 19.331 3 17.797 3 14.727v-2.545c0-2.963 0-4.445.469-5.628c.754-1.903 2.348-3.403 4.37-4.113C9.095 2 10.668 2 13.818 2c1.798 0 2.698 0 3.416.252c1.155.406 2.066 1.263 2.497 2.35C20 5.278 20 6.125 20 7.818V10" />
                                                <path d="M3 12a3.333 3.333 0 0 1 3.333-3.333c.666 0 1.451.116 2.098-.057A1.67 1.67 0 0 0 9.61 7.43c.173-.647.057-1.432.057-2.098A3.333 3.333 0 0 1 13 2" />
                                              </g>
                                            </svg>
                                            <Table
                                              ref={tableRef}
                                              id="table"
                                              appearance={appearance}
                                              dataExport={dataExport}
                                              dataSource={ndcDetails}
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
                          ) : (null)
                        }

                        {/* ======================================= */}
                      </div>
                      {/* ======================================= */}
                    </div>
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

export default Declaration

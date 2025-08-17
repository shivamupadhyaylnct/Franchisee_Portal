import axios from 'axios';
import  { useEffect, useState } from 'react'
import { toast } from "react-toastify";
import 'react-toastify/dist/ReactToastify.css';
// import { BeatLoader } from 'react-spinners';
import { baseURL, base } from '../base';
import { config } from '../config';
import { useNavigate } from 'react-router-dom';
import { Button } from '@mui/material';


function cmrNdcDetails() {

  const [file,setFile]= useState(null); 
    // console.log("file is : ", file)

  const [storeCodes, setStoreCodes] = useState([])
  const [selectedStoreCode, setSelectedStoreCode] = useState("")

  const [franchise, setFranchise]= useState([])
  const [selectedFranchiseName, setSelectedFranchiseName] = useState("");

  const financialYear = ["2022-2023", "2023-2024", "2024-2025", "2025-2026"]
  const [selectedFinancialYear, setSelectedFinancialYear] = useState("");
  const financialQuarter = ["Q1", "Q2", "Q3", "Q4"]
  const [selectedFinancialQuarter, setSelectedFinancialQuarter] = useState("");


  const handleFileChange = (e) => {
    setFile(e.target.files[0]);
  };

  const navigate = useNavigate();
  const handleNavClick = (e, value) => {
      e.preventDefault();
      navigate(value);
  };
//===============================================
  useEffect(()=>{
    const fetchAllFranchise = async()=>{
     try {
      const res = await axios.get(`${baseURL}${config.getAllFranchiseDetails}`)
      setFranchise(res.data)
     } catch (error) {
      toast.error("Error Fetching Franchisee Details.");
      console.log("Error Fetching Details", error.message)
     }
    }
    fetchAllFranchise();
  },[])

  useEffect(() => {
    if (selectedFranchiseName) {
      (async () => {
        const newData = await getStoreCodes();
        console.log('Fetched StoreCodes response:', newData);

        if (newData?.ALL_STORE) {
          setStoreCodes(newData.ALL_STORE);
          setSelectedStoreCode(newData.ALL_STORE[0]?.LEGACY_CODE || '');
        } else {
          setStoreCodes([]);
          setSelectedStoreCode('');
        }
      })();
    } else {
      setStoreCodes([]);
      setSelectedStoreCode('');
    }
  }, [selectedFranchiseName]);
  
//==========================================

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

  // Common for Franchise Name, Financial year and financial quarter using name attribute
  const handleChange = (event) => {
    const { name, value } = event.target; //Destructring

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


  const handleSubmit = async () => {
      console.groupCollapsed()
      console.log("1 name",selectedFranchiseName)
      console.log("year",selectedFinancialYear)
      console.log("quarter",selectedFinancialQuarter)
      console.log("store",selectedStoreCode)
      console.groupEnd()

    try {
      if (!selectedFranchiseName || !selectedStoreCode || !selectedFinancialYear || !selectedFinancialQuarter || !file) {
          if (!selectedFranchiseName) {
           toast.warning("Please provide Franchise Name");
          } else if (!selectedStoreCode) {
           toast.warning("Please provide Store Code");
          } else if (!selectedFinancialYear) {
           toast.warning("Please provide Financial Year");
          } else if (!selectedFinancialQuarter) {
           toast.warning("Please provide Financial Quarter");
          } else if (!file){
            toast.warning("Select a file");
          }
          return;
     }
      else {
        const formData = new FormData();
        formData.append('file',file)
        formData.append('storecode',selectedStoreCode.replace(/^0+/, ''))
        formData.append('quarter',selectedFinancialQuarter)
        formData.append('year',selectedFinancialYear)
        // console.log("form data is : ",formData)
        
        const response = await axios.post(`${baseURL}${config.uploadcmrndcfile}`, formData);
        
       if (response?.data?.file_name) {
          toast.success(`File - "${response.data.file_name}" uploaded successfully`);
          // reset
            setFile(null);
            setSelectedFranchiseName(""); 
            setSelectedStoreCode("");
            setSelectedFinancialYear("");
            setSelectedFinancialQuarter("");

        } else {
          toast.error("File not uploaded");
        }
      }
      
    } catch (error) {
      console.error("file Upload failed : ",error.message);
      toast.error('file Upload failed');
    }
  };


  return (
    <>
            {/* <!--  BEGIN CONTENT AREA  --> */}
      <div id="content" className="main-content">
        <div className="layout-px-spacing1">

          <div className="middle-content container-xxl p-0">
            <div id="tabsSimple" className="col-xl-12 col-12 layout-spacing mt-3">
              
              <div className="statbox widget">
      
                  {/* ================= (Back and addUser Button) ================== */}

                    <div className="box box-shadow d-flex align-items-center justify-content-between ">
                        <h5 className="p-3" >CMR NDC Details</h5>
                        <div className="d-flex gap-2 m-3">
                            <a href="/admin/dashboard"
                                className="btn btn-primary"
                                onClick={(e) => handleNavClick(e, "/admin/dashboard")}>
                                <i className="fa fa-arrow-left me-2"></i> Back
                            </a>
                        </div>
                    </div>
                
                    {/* ======================================= */}
                    <div className="widget-content widget-content-area pt-0">
                     <div className="tab-content" id="pills-tabContent">
                      <div id="pills-profile-icon" role="tabpanel" aria-labelledby="pills-profile-icon-tab" tabindex="0">
                        <div className="row p-3">
                          <div className="form border rounded p-3" style={{ border: "2px solid black" }}>
                            <div className="row">

                              <div className="col-md-4 mb-3">
                                <div className="form-group">
                                  <label htmlFor="fullName">Franchise Name </label>

                                  <select name="selectedFranchiseName" id="country" className="form-select" value={selectedFranchiseName}
                                    onChange={handleChange}>
                                    <option value="" disabled>Select Franchise Name</option>
                                    {franchise.map((item) => (
                                      <option key={item.franchiseeUID} value={item.franchiseeName}>{item.franchiseeName}</option>
                                    ))}
                                  </select>
                                </div>
                              </div>

                              <div className="col-md-4 mb-3">
                                <div className="form-group">
                                  <label htmlFor="address">Store Code</label>
                                  <select name="selectedStoreCode"
                                    id="country" className="form-select"
                                    value={selectedStoreCode}
                                    onChange={handleChange}
                                  >
                                    <option value="" disabled>
                                      Select Store Code
                                    </option>
                                    
                                    {
                                      storeCodes.map((option) => (
                                        <option key={option.LEGACY_CODE}
                                          value={option.LEGACY_CODE}>
                                          {option.LEGACY_CODE.replace(/^0+/, '')}
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

                               <div className="col-md-6 mt-2 mb-3">
                                <div className="form-group">
                                  <label htmlFor="location">Choose file </label> <br/>
                                  <label htmlFor="file-upload" style={{ cursor: 'pointer' }}>
                                      <Button variant="contained" component="span"> 
                                        Choose File 
                                      </Button>
                                    </label>
                                    <input
                                      id="file-upload"
                                      type="file"
                                      style={{ display: 'none' }}
                                      onChange={handleFileChange}
                                    />
                                    <spane> <b>{file ? file.name : ''}</b></spane>
                                </div>
                              </div>

                              <div className="col-md-2 mt-5 mb-3">
                                <div className="form-group text-end">
                                  <Button onClick={handleSubmit} variant="contained" color="primary" style={{ marginLeft: '1rem' }}>
                                      Submit File
                                    </Button>
                                </div>
                              </div>
                            </div>
                          </div>
                        </div>
                        {/* ======================================= */}

                        {/* {
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
                                              appearance={{ alternationStart: 0, alternationCount: 2, }}
                                              dataExport={{ view: true, viewStart: 0, viewEnd: 50 }}
                                              dataSource={ndcDetails}
                                              paging={true}
                                              pageIndex={0}
                                              pageSize={10}
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
                        } */}

                        {/* ======================================= */}
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

export default cmrNdcDetails

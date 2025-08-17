import React, { useEffect, useState, useRef } from "react";
import DatePicker from "react-datepicker";
import "react-datepicker/dist/react-datepicker.css";
import flatpickr from "flatpickr";
import "flatpickr/dist/flatpickr.min.css";
import { Table } from 'smart-webcomponents-react/table';
import 'smart-webcomponents-react/source/styles/smart.default.css';
import axios from 'axios';
import { toast } from "react-toastify";
import 'react-toastify/dist/ReactToastify.css';
import { BeatLoader } from 'react-spinners';
import { baseURL } from "../../base";
import { config } from "../../config";

const CustomFlatpickr = ({ onChange, minDate, maxDate }) => {
  const inputRef = useRef();

  useEffect(() => {
    flatpickr(inputRef.current, {
      enableTime: false,
      dateFormat: "Y-m-d",
      minDate: minDate || null,
      maxDate: maxDate || null,
      onChange: (selectedDates) => {
        if (onChange) onChange(selectedDates[0]);
      },
    });
  }, [minDate, maxDate]);

  return <input ref={inputRef} className="form-control flatpickr flatpickr-input active" type="text" placeholder="Select Date.." />;
};


function formatDateTableDisplay(value) {
  if (!value || typeof value !== 'string' || value.length !== 8) return '';
  const year = value.slice(0, 4);
  const month = value.slice(4, 6);
  const day = value.slice(6, 8);
  return `${year}/${month}/${day}`;
}

function Ledger() {
  const tableRef = useRef();
  const user = localStorage.getItem("user_details");
  const userDetails = JSON.parse(user)
  const [fromDate, setFromDate] = useState("");
  const [toDate, setToDate] = useState(null);
  const company = ["MG", "IW"]
  const [companyCodes, setCompanyCodes] = useState(company[0] || "");
  const [ledgerDetails, setLedgerDetails] = useState({});
  const [ledgerType, setLedgerType] = useState("ledger")
  const [loading, setLoading] = useState(false);

  const [vendorCodeWithName, setVendorCodeWithName] = useState([]);
  // console.log("All vender code fetched are=> ", vendorCodeWithName);

  const [selectedFranchiseName, setSelectedFranchiseName] = useState("");


      useEffect(()=>{
        const fetchVendorFranchisee = async () => {
        try {
            const vendorCodes = userDetails.map(u => u.UserName);
            console.log("vendorCodes =:",userDetails)
            
            const res = await axios.post(`${baseURL}${config.getVendorWithFranchisee}`,{vendorCodes});
            if (res.data.code === 200) {
                setVendorCodeWithName(res.data.data);
            }
        }  catch (err) {
            console.error("Error fetching vendor:", err);
            } 
        };
        fetchVendorFranchisee();
    },[selectedFranchiseName])



  const appearance = {
    alternationStart: 0,
    alternationCount: 2,
  };

  const dataExport = {
    view: true,
    viewStart: 0,
    viewEnd: 50
  };
  const paging = true;
  const pageIndex = 0;
  const pageSize = 10;

  const columns = [{
    label: 'Claim Date',
    dataField: 'BUDAT',
  },
  {
    label: 'Claim No.',
    dataField: 'BELNR',
    dataType: 'string'
  },
  {
    label: 'Description',
    dataField: 'SGTXT',
    dataType: 'string'
  },
  {
    label: 'Gross Amt',
    dataField: 'GR_AMOUNT',
    dataType: 'string'
  },
  {
    label: 'Tax Amt',
    dataField: 'TAX_AMOUNT',
    dataType: 'string'
  },
  {
    label: 'Net. Amount',
    dataField: 'NetAmnt',
  },
  {
    label: 'Payment Doc. No.',
    dataField: 'AUGBL',
    dataType: 'string'
  },
  {
    label: 'Payment Date',
    dataField: 'AUGDT',
  },
  {
    label: 'Reference',
    dataField: 'XBLNR',
    dataType: 'string'
  },
  ];

  const handleChange = (event) => {
    const { name, value } = event.target; // destructring

    if (name === 'companyCodes') {
      setCompanyCodes(value);
    } else if (name === 'ledger-type') {
      setLedgerType(value);
    } else if (name === 'selectedFranchiseName') {
      setSelectedFranchiseName(value);
    }
  }


  function formatDateLocal(dateInput) {
    const date = new Date(dateInput);
    const yyyy = date.getFullYear();
    const mm = String(date.getMonth() + 1).padStart(2, '0'); // Months start at 0
    const dd = String(date.getDate()).padStart(2, '0');
    return `${yyyy}${mm}${dd}`;
  }

  function formatDateDisplay(dateInput) {
    const date = new Date(dateInput);
    const yyyy = date.getFullYear();
    const mm = String(date.getMonth() + 1).padStart(2, '0');
    const dd = String(date.getDate()).padStart(2, '0');
    return `${yyyy}/${mm}/${dd}`;
  }

  const handleSubmit = async () => {

    try {
      if (companyCodes == "") {
        toast.error("Provide company");
        return;
      }
       if (selectedFranchiseName == "") {
        toast.error("Provide vendor Code");
        return;
      }
      if (fromDate == "" || fromDate == null) {
        toast.error("Provide From Date");
        return;
      }
      if (toDate == "" || toDate == null) {
        toast.error("Provide To Date");
        return;
      }
      else {
        setLoading(true);
        const response = await axios.post(`${baseURL}${config.getledgerdetails}`, {
          company: companyCodes,
          fromDate: fromDate ? formatDateLocal(fromDate) : "",
          toDate: toDate ? formatDateLocal(toDate) : "",
          storeUID: selectedFranchiseName,
          ledgerType: ledgerType
        });
        if (response.data.code === 400) {
          toast.error("Provide Mandatory fields - company,fromDate,toDate ");

        } else if (response.data.code === 201) {
          //console.log(response.data)
          if (response.data.ledger_details.INT_LEDGER.length > 0) {
            let originalData = response.data.ledger_details
            const formatted = response.data.ledger_details.INT_LEDGER.map(row => ({
              ...row,
              BUDAT: formatDateTableDisplay(row.BUDAT),
              AUGDT: formatDateTableDisplay(row.AUGDT),
              NetAmnt: (row.NET_DEBIT - row.NET_CREDIT).toFixed()
            }));

            originalData.INT_LEDGER = formatted;
            //console.log(originalData)
            setLedgerDetails(originalData)
            setTimeout(() => {
              setLoading(false);
            }, 1000);
          }
          else {
            setLedgerDetails({})
            setLoading(false);
          }
        }
        else {
          setLoading(false);
          setLedgerDetails({})
        }

      }

    } catch (error) {
      //console.error('Error:', error);
    }
  };

  // const handleCsvBtnClick = () => {
  //   setTimeout(() => {
  //     if (tableRef.current) {
  //       tableRef.current.exportData('csv', 'ledger.csv');
  //     } else {
  //       console.log("Table ref not ready");
  //     }
  //   }, 100);
  // };

    const handleCsvBtnClick = () => {
      setTimeout(() => {
        if (!tableRef.current) {
          console.log("Table ref not ready");
          return;
        }

        const tableData = tableRef.current.dataSource || [];
        if (tableData.length === 0) {
          toast.error("No data to export");
          return;
        }

        // Extract visible column fields and labels
        const visibleFields = columns.map(col => col.dataField);
        const headerLabels = columns.map(col => `"${col.label}"`);
        
        // Start building CSV
        let csvContent = headerLabels.join(",") + "\n";

        tableData.forEach(row => {
          const rowValues = visibleFields.map(field => {
            let value = row[field] ?? '';
            value = value.toString().replace(/[\r\n]+/g, ' ').replace(/\s+/g, ' ').trim();
            if (isNaN(value) || value.includes(',') || value.includes(' ')) {
              value = `"${value}"`;
            }
            return value;
          });
          csvContent += rowValues.join(",") + "\n";
        });

        // Trigger download
        const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
        const link = document.createElement("a");
        if (link.download !== undefined) {
          const url = URL.createObjectURL(blob);
          link.setAttribute("href", url);
          link.setAttribute("download", "ledger.csv");
          link.style.visibility = "hidden";
          document.body.appendChild(link);
          link.click();
          document.body.removeChild(link);
        }
      }, 100);
    };


  return (
    <>
      <div id="content" className="main-content">
        <div className="layout-px-spacing">

          <div className="middle-content container-xxl p-0">
            <div className="card mt-3">
              <div className="card-body">
                <div className="row">
                  <h5>Ledger Details</h5>
                  <div className="form mt-2">
                    <div className="row">

                      <div className="col-md-4 mb-3">
                        <div className="form-group">
                          <label htmlFor="fullName">Company Code </label>
                          <select name="companyCodes" id="country" className="form-select" value={companyCodes}
                            onChange={handleChange}>
                            {company.map((option) => (
                              <option key={option} value={option}>{option}</option>
                            ))}
                          </select>
                        </div>
                      </div>

                      <div className="col-md-4 mb-3">
                        <div className="form-group">
                          <label htmlFor="fullName">Vendor Code </label>
                          <select name="selectedFranchiseName" id="country" className="form-select" value={selectedFranchiseName}
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
                          <label htmlFor="fullName">From Date </label>
                          {/* <input id="fromdate" className="form-control flatpickr flatpickr-input active" type="text" placeholder="Select Date.." /> */}
                          <CustomFlatpickr
                                value={fromDate}
                                maxDate={new Date()} // from date must be < today
                                onChange={(date) => {
                                  setFromDate(date);
                                  if (toDate && date && new Date(toDate) < new Date(date)) {
                                    setToDate(null); // reset if current toDate is invalid
                                  }
                                }}
                              />
                        </div>
                      </div>

                      <div className="col-md-4 mb-3">
                        <div className="form-group">
                          <label htmlFor="fullName">To Date </label>
                          {/* <input id="todate" className="form-control flatpickr flatpickr-input active" type="text" placeholder="Select Date.." /> */}
                          <CustomFlatpickr
                            value={toDate}
                            minDate={fromDate || null}
                            maxDate={new Date()} // today is upper bound
                            onChange={(date) => setToDate(date)}
                          />
                        </div>
                      </div>


                      <div className="col-md-4 mb-3">
                        <div className="form-group">
                          <label htmlFor="fullName">Ledger Type </label><br />
                          <div className="form-check form-check-primary form-check-inline">
                            <input className="form-check-input" value="legder"
                              onChange={handleChange} type="radio" name="ledger-type" id="form-check-radio-default" defaultChecked="true" />
                            <label className="form-check-label" htmlFor="form-check-radio-default">
                              Ledger
                            </label>
                          </div>
                          <div className="form-check form-check-primary form-check-inline">
                            <input className="form-check-input" value="gst"
                              onChange={handleChange} type="radio" name="ledger-type" id="form-check-radio-default" />
                            <label className="form-check-label" htmlFor="form-check-radio-default">
                              To Raise Invoice for GST
                            </label>
                          </div>
                        </div>
                      </div>






                      <div className="col-md-12 mt-3 mb-3">
                        <div className="form-group text-start">
                          <button className="btn btn-secondary" onClick={handleSubmit}>View Statement</button>
                        </div>
                      </div>
                      <hr />

                      <div className="col-lg-12 mt-3">
                        <div className="d-flex justify-content-between align items center">
                          <div className=""><b>Period : <span className="text-danger">   {fromDate && toDate && ledgerDetails?.OPEN_BALANCE ? (
                            <span className="text-danger"> {formatDateDisplay(fromDate)} to {formatDateDisplay(toDate)}</span>
                          ) : null}</span></b></div>
                          {/* <div className=""><b>Opening Balance : <span className="text-danger">{ledgerDetails?.OPEN_BALANCE}</span></b></div>
                          <div className=""><b>Closing Balance : <span className="text-danger">{ledgerDetails?.CLOSE_BALANCE}</span></b></div> */}

                        </div>
                      </div>

                    </div>

                  </div>

                </div>
              </div>
            </div>
            {
              Array.isArray(ledgerDetails?.INT_LEDGER) && ledgerDetails.INT_LEDGER.length > 0 ? (
                <>
                  {loading ? (
                    <>
                      <div style={{ display: 'flex', justifyContent: 'center', marginTop: '4rem' }}>
                        <BeatLoader color="#0257A7" height={4} width={100} loading={loading} />
                      </div>
                    </>
                  ) : (
                    <div className="card mt-3">
                      <div className="card-body">
                        <div className="row">
                          <div className="col-xl-12 col-lg-12 col-sm-12  layout-spacing">
                            <div className="statbox widget box box-shadow">
                              <div className="widget-content widget-content-area">
                                <svg xmlns="http://www.w3.org/2000/svg" width="34" height="34" viewBox="0 0 24 24" onClick={handleCsvBtnClick} style={{ cursor: "pointer" }}>
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
                                  dataSource={ledgerDetails?.INT_LEDGER}
                                  paging={paging}
                                  pageIndex={pageIndex}
                                  pageSize={pageSize}
                                  columns={columns}
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


          </div>

        </div>

      </div>
    </>
  )
}

export default Ledger
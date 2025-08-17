import React, { useEffect, useState, useRef } from "react";
import flatpickr from "flatpickr";
import "flatpickr/dist/flatpickr.min.css";
import { Table } from 'smart-webcomponents-react/table';
import 'smart-webcomponents-react/source/styles/smart.default.css';
import axios from 'axios';
import { toast } from "react-toastify";
import 'react-toastify/dist/ReactToastify.css';
import monthSelectPlugin from "flatpickr/dist/plugins/monthSelect";
import { BeatLoader } from 'react-spinners';
import { baseURL } from "../../base";
import { config } from "../../config";

// Import Flatpickr styles
import "flatpickr/dist/flatpickr.min.css";
import "flatpickr/dist/plugins/monthSelect/style.css";

const CustomFlatpickr = ({ onChange }) => {
    const inputRef = useRef();
    useEffect(() => {
        flatpickr(inputRef.current, {
            dateFormat: "Y-m", // Year-Month format
            plugins: [
                new monthSelectPlugin({
                    shorthand: true,
                    dateFormat: "Y-m",
                    altFormat: "F Y",
                }),
            ],
            onChange: (selectedDates) => {
                if (onChange) onChange(selectedDates);
            },
        });
    }, []);
    return <input ref={inputRef} className="form-control flatpickr flatpickr-input active" type="text" placeholder="Select Month & Year" />;
};

function CreditDebit() {
    const tableRef = useRef();
    const user = localStorage.getItem("user_details");
    const userDetails = JSON.parse(user)
    const [storeCodes, setStoreCodes] = useState([])
    const [selectedStoreCode, setSelectedStoreCode] = useState("")
    const [fromDate, setFromDate] = useState(null);
    const [creditDebitList, setCreditDebitList] = useState([])
    const [loading, setLoading] = useState(false);
    
    const [vendorCodeWithName, setVendorCodeWithName] = useState([]);
    // console.log("All vender code fetched are=> ", vendorCodeWithName);
    const [selectedFranchiseName, setSelectedFranchiseName] = useState("");

        useEffect(()=>{
        const fetchVendorFranchisee = async () => {
        try {
            const vendorCodes = userDetails.map(u => u.UserName);
            // console.log("vendorCodes =:",userDetails)
            
            const res = await axios.post(`${baseURL}${config.getVendorWithFranchisee}`,{vendorCodes});
            if (res.data.code === 200) {
                setVendorCodeWithName(res.data.data);
                // console.log("hgsvdh",res.data.data)
            }
        } catch (err) {
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

    const columns = [

        {
            label: 'Vendor Code',
            dataField: 'vendorCode',
            dataType: 'string',
            width: 150,
        },
        {
            label: 'Invoices',
            dataField: 'fileName',
            dataType: 'string',
            width: 150,
            formatFunction: function (settings) {
                const row = settings.data;
                if (row && row.downloadLink) {
                    settings.template = `<a href="${row.downloadLink}" download="${row.downloadName}">Download</a>`;
                } else {
                    settings.template = 'N/A';
                }
            }
        },
        {
            label: 'Type',
            dataField: 'type',
            dataType: 'string',
            width: 150,
        },
    ];


    const handleChange = (event) => {
        const { name, value } = event.target; //Destructring

        if (name === 'selectedFranchiseName') {
            setSelectedFranchiseName(value);
        } else if (name === 'selectedCommission') {
            setSelectedCommission(value);
        } else if (name === 'selectedStoreCode') {
            setSelectedStoreCode(value);
        }
    };


    async function getStoreCodes() {
        const response = await axios.post(`${baseURL}${config.getallstoredetails}`, {
            storeUID: selectedFranchiseName
        });
        try {
            if (response.data.code === 201) {
                return response.data.all_store_details;
            }
        } catch (error) {
            let errorMessage = []
            errorMessage = Promise.resolve(error)
            return errorMessage
        }
    }


    useEffect(() => {
        (async () => {
            if (selectedFranchiseName != "") {
                const newData = await getStoreCodes();
                //console.log("Fetched StoreCodes response:", newData);

                if (newData?.ALL_STORE) {
                    setStoreCodes(newData.ALL_STORE);
                    setSelectedStoreCode(newData.ALL_STORE[0].LEGACY_CODE);
                } else {
                    setSelectedStoreCode(""); // fallback
                }
            }
        })();
    }, [selectedFranchiseName])




    const handleSubmit = async () => {
        try {
            if (selectedStoreCode == "") {
                toast.error("Provide Store Code");
                return;
            }
            else if (fromDate == "" || fromDate == null) {
                toast.error("Provide Month & Year");
                return;
            }
            else {
                const date = new Date(fromDate)
                const yyyy = date.getFullYear();
                const mm = String(date.getMonth() + 1).padStart(2, '0');
                let data = {
                    storeCode: selectedStoreCode,
                    year: yyyy,
                    month: mm
                }
                //console.log(data)
                setLoading(true);
                const response = await axios.post(`${baseURL}${config.getcreditdebit}`, data);
                if (response.data.code === 400) {
                    toast.error("Provide Mandatory fields - Store code,Month & Year ");

                } else if (response.data.code === 201) {
                    if (response.data.data.length > 0) {
                        //console.log(response.data)
                        const tempData = response.data.data
                        tempData.forEach((item) => {
                            const byteCharacters = atob(item.fileData);
                            const byteNumbers = new Array(byteCharacters.length)
                                .fill(0)
                                .map((_, i) => byteCharacters.charCodeAt(i));
                            const byteArray = new Uint8Array(byteNumbers);
                            const blob = new Blob([byteArray], { type: "application/pdf" });
                            const url = URL.createObjectURL(blob);
                            item.downloadLink = url;
                        });

                        //console.log(tempData)
                        setCreditDebitList(tempData)
                        setTimeout(() => {
                            setLoading(false);
                        }, 1000);
                    }
                    else {
                        setCreditDebitList([])
                        setLoading(false);
                        toast.info("No Records Found")
                    }
                }
                else {
                    setLoading(false);
                    setCreditDebitList([])
                }

            }

        } catch (error) {
            //console.error('Error:', error);
        }
    };


    return (
        <>
            <div id="content" className="main-content">
                <div className="layout-px-spacing">

                    <div className="middle-content container-xxl p-0">
                        <div className="card mt-3">
                            <div className="card-body">
                                <div className="row">
                                    <h5>Credit and Debit Notes</h5>
                                    <div className="form mt-2">
                                        <div className="row">

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
                                                    <label htmlFor="address">Store Code</label>
                                                    <select name="selectedStoreCode" id="country" className="form-select" value={selectedStoreCode}
                                                        onChange={handleChange}>
                                                        <option value="">
                                                            Select Store Code
                                                        </option>
                                                        {storeCodes.map((option) => (
                                                            <option key={option.LEGACY_CODE} value={option.LEGACY_CODE}>{option.LEGACY_CODE.replace(/^0+/,'')}</option>
                                                        ))}
                                                    </select>
                                                </div>
                                            </div>


                                            <div className="col-md-4 mb-3">
                                                <div className="form-group">
                                                    <label htmlFor="fullName"> Year & Month </label>
                                                    <CustomFlatpickr value={fromDate} onChange={(date) => setFromDate(date)} />
                                                </div>
                                            </div>


                                            <div className="col-md-12 mt-3">
                                                <div className="form-group text-end">
                                                    <button className="btn btn-secondary" onClick={handleSubmit}>View Statement</button>
                                                </div>
                                            </div>

                                        </div>

                                    </div>

                                </div>
                            </div>
                        </div>
                        {
                            creditDebitList.length > 0 ? (
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
                                                                <Table
                                                                    ref={tableRef}
                                                                    id="table"
                                                                    appearance={appearance}
                                                                    dataExport={dataExport}
                                                                    dataSource={creditDebitList}
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

                    </div>

                </div>
            </div>
        </>
    )
}

export default CreditDebit
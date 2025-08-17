import axios from 'axios';
import React, { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { toast } from 'react-toastify';
import Table from 'smart-webcomponents-react/table';
import { MultiSelect } from 'primereact/multiselect';
import "primereact/resources/themes/saga-blue/theme.css";
import "primereact/resources/primereact.min.css";
import "primeicons/primeicons.css";

import Swal from 'sweetalert2';
import { baseURL } from '../base';
import { config } from '../config';
import { Dialog, DialogActions, DialogContent, DialogTitle, } from "@mui/material";
import IconButton from '@mui/material/IconButton';
import CloseIcon from '@mui/icons-material/Close';
import { Grid2 as Grid } from '@mui/material';




function franchiseDetails() {
  const navigate = useNavigate();
  const [vendorCodes, setVendorCodes] = useState([])
  const [selectedVendorCode, setSelectedVendorCode] = useState([])
  console.log("selectedVendorCodes:", selectedVendorCode);
  const [franchiseeName, setfranchiseeName] = useState([])
  const [selectedfranchiseeName, setSelectedfranchiseeName] = useState("")
  const [mapMobileNumber, setMapMobileNumber] = useState("")
  const [isMappingPopup, setIsMappingPopup] = useState(false)
  const [isAddUserPopup, setIsAddUserPopup] = useState(false)

  const [franchiseeData, setFranchiseeData] = useState([]);
  const [addFranchiseeForm, setAddFranchiseeForm] = useState({
    franchiseeName: "",
    email: "",
    mobileNumber: "",
    address: "",
    city: "",
    state: "",
    pincode: "",
  });



  //=========================================================================
  const handleNavClick = (e, value) => {
    e.preventDefault();
    navigate(value);
  };

    const handleClose = ()=>{
        setAddFranchiseeForm({ franchiseeName: "", address: "", city: "", state: "", mobileNumber: "", pincode: "", email: "", panno: "" });
    }
  //===========================( Populated Franchisee name AND vendor code )============================================

  const fetchFranchiseeName = async () => {
    try {
      const res = await axios.get(`${baseURL}${config.getAllFranchisees}`);
      setfranchiseeName(res.data.franchisees);
    } catch (error) {
      console.error("Error fetching franchisees details", error);
    }
  };

  const fetchVendors = async () => {
    try {
      const res = await axios.get(`${baseURL}${config.getAllVendors}`);
      setVendorCodes(res.data.vendors);
    } catch (error) {
      console.error("Error fetching vendor codes", error);
    }
  };


  const handleMap = async (mobileNumber) => {
    try {
      // Fetch franchisee details using mobile number
      const response = await axios.get(`${baseURL}${config.adminGetFranchiseDetails}${mobileNumber}/`);
      const franchisee = response.data;

      // Set the selected name and mobile number (read-only)
      setSelectedfranchiseeName(franchisee.franchiseeName);
      setMapMobileNumber(franchisee.mobileNumber);

      // Fetch vendors for dropdown
      await fetchVendors();
      await fetchFranchiseeName();

      setIsMappingPopup(true);
    } catch (error) {
      console.error("Failed to load franchisee data for mapping", error);
      toast.error("Failed to fetch franchisee details.");
    }
  };


  const handleMapSave = async () => {
    console.groupCollapsed()
    console.log("Selected Franchisee Name:", selectedfranchiseeName);
    console.log("Selected Vendor Code:", selectedVendorCode);
    console.log("Map Mobile Number:", mapMobileNumber);
    console.log("Franchisee List:", franchiseeName); // full list
    console.groupEnd()

    // Find the franchiseeUID from name
    const selectedFranchisee = franchiseeName.find(
      (f) => f.franchiseeName === selectedfranchiseeName
    );

    // Find the vendorUID from code
    const selectedVendors = vendorCodes.filter((v) =>
        selectedVendorCode.includes(v.vendorCode)
      );

    // console.log("Vendor Codes List:", selectedVendor); // full list
    if (!selectedFranchisee || !selectedVendors || !mapMobileNumber) {
      toast.error("Please fill all fields correctly.");
      return;
    }

    const payload = {
      franchiseeUID: selectedFranchisee.franchiseeUID,
      vendorUID: selectedVendors.map((v) => v.vendorUID),
      mobileNumber: Number(mapMobileNumber),
      vendorCode: selectedVendors.map((v) => v.vendorCode),
    };

    try {
      const res = await axios.post(`${baseURL}${config.franchiseVendorMapping}`, payload);
      if (res.data.code === 200) {
        toast.success("Mapping saved successfully!");

        // Reset form fields after successful save
        setSelectedfranchiseeName("");
        setSelectedVendorCode([]);
        setMapMobileNumber("");
      } else {
        toast.error("Error: " + res.data.message);
      }
    } catch (error) {
      console.error("API Error:", error);
      toast.error("Something went wrong while saving.");
    }
  };

  // =============================== ( Model form Data handles and Save Handle) ==================================

  // form data input via name and value
  const handleChange = (e) => {
    setAddFranchiseeForm({
      ...addFranchiseeForm,
      [e.target.name]: e.target.value
    });
  };



  const checkIfMobileExists = async (mobileNumber) => {
    try {
      const response = await axios.get(`${baseURL}${config.adminGetFranchiseDetails}${mobileNumber}/`);
      return response.data ? true : false; // If data exists, return true
    } catch (error) {
      if (error.response && error.response.status === 404) {
        return false; // Mobile number not found, okay to add
      }
      throw error; // Other error
    }
  };

  const handleSave = async () => {
    const { mobileNumber } = addFranchiseeForm;
    // console.log("gdsvfkahsdfuasygdf==>>",addFranchiseeForm)
    try {

      const exists = await checkIfMobileExists(mobileNumber);
      if (exists) {
        const response = await axios.patch(`${baseURL}${config.updateSpecificFranchise}${mobileNumber}/`, addFranchiseeForm);
        if (response.data.code === 200) {
          toast.success("Franchisee updated successfully!");
          fetchFranchisee();
          setAddFranchiseeForm({ franchiseeName: "", address: "", city: "", state: "", mobileNumber: "", pincode: "", email: "", panno: "" });
        } else {
          toast.error("Failed to update Franchisee.");
        }
        return;
      }


      const response = await axios.post(`${baseURL}${config.addFranchiseDetails}`, addFranchiseeForm);
      if (response.data.code === 200) {
        toast.success("Franchisee added successfully!");
        fetchFranchisee();// this will refresh the table and rerender the new data
        // this will Clear input fields once data inserted successfully
        setAddFranchiseeForm({
          franchiseeName: "", address: "", city: "", state: "", mobileNumber: "", pincode: "", email: "", panno: ""
        });
        return response.data;
      } else {
        toast.error("Failed to add Franchisee. Please try again.");
      }
    } catch (error) {
      console.error("Error saving Franchisee:", error);
      if (error.response) {
        console.log("Backend error response:", error.response.data);
        toast.error(JSON.stringify(error.response.data.message));
      }
    }
  };


  //================= ( table Edit and Delete Button , column  )==============================================

  const columns = [
    {
      label: 'S. No',
      dataField: 'sno',
      dataType: 'string',
      width: 150
    },
    {
      label: 'Franchisee Name',
      dataField: 'franchiseeName',
      dataType: 'string',
      width: 150
    },
    {
      label: 'Email',
      dataField: 'email',
      dataType: 'string',
      width: 150
    },
    {
      label: 'Mobile Number',
      dataField: 'mobileNumber',
      dataType: 'number',
      width: 150
    },
    {
      label: 'Address',
      dataField: 'address',
      dataType: 'string',
      width: 150
    },
    {
      label: 'City',
      dataField: 'city',
      dataType: 'string',
      width: 150
    },
    {
      label: 'State',
      dataField: 'state',
      dataType: 'string',
      width: 150
    },
    {
      label: 'Pin Code',
      dataField: 'pincode',
      dataType: 'number',
      width: 150
    },
    {
      label: 'Action',
      dataField: 'action',
      width: 150,
      formatFunction: (settings) => {
        const mapDiv = document.createElement('span');
        mapDiv.className = "downBtn";
        mapDiv.style.margin = "10px";
        mapDiv.innerHTML = `<span style="cursor:pointer;" title="Map">
              <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 576 512">
                <path fill="currentColor" d="m384 476.1l-192-54.9V35.9l192 54.9zm32-1.2V88.4l127.1-50.9c15.8-6.3 32.9 5.3 32.9 22.3v334.8c0 9.8-6 18.6-15.1 22.3L416 474.8zM15.1 95.1L160 37.2v386.5L32.9 474.5C17.1 480.8 0 469.2 0 452.2V117.4c0-9.8 6-18.6 15.1-22.3"/>
              </svg>
            </span>`;
        const editDiv = document.createElement('span');
        editDiv.className = "downBtn";
        editDiv.style.margin = "10px";
        editDiv.innerHTML = `<span style="cursor:pointer;" title="Edit">
              <svg xmlns="http://www.w3.org/2000/svg" width="28" height="28" viewBox="0 0 24 24">
                <path fill="currentColor" d="M3.548 20.938h16.9a.5.5 0 0 0 0-1h-16.9a.5.5 0 0 0 0 1M9.71 17.18a2.6 2.6 0 0 0 1.12-.65l9.54-9.54a1.75 1.75 0 0 0 0-2.47l-.94-.93a1.79 1.79 0 0 0-2.47 0l-9.54 9.53a2.5 2.5 0 0 0-.64 1.12L6.04 17a.74.74 0 0 0 .19.72a.77.77 0 0 0 .53.22Zm.41-1.36a1.47 1.47 0 0 1-.67.39l-.97.26l-1-1l.26-.97a1.5 1.5 0 0 1 .39-.67l.38-.37l1.99 1.99Zm1.09-1.08l-1.99-1.99l6.73-6.73l1.99 1.99Zm8.45-8.45L18.65 7.3l-1.99-1.99l1.01-1.02a.75.75 0 0 1 1.06 0l.93.94a.754.754 0 0 1 0 1.06"/>
              </svg>
            </span>`;
        const deleteDiv = document.createElement('span');
        deleteDiv.className = "downBtn";
        deleteDiv.style.margin = "10px";
        deleteDiv.innerHTML = `<span  style="cursor:pointer;" title="Delete">
              <svg xmlns="http://www.w3.org/2000/svg"  width="28" height="28" viewBox="0 0 24 24">
                <path fill="currentColor" d="M12 4c-4.419 0-8 3.582-8 8s3.581 8 8 8s8-3.582 8-8s-3.581-8-8-8m3.707 10.293a.999.999 0 1 1-1.414 1.414L12 13.414l-2.293 2.293a.997.997 0 0 1-1.414 0a1 1 0 0 1 0-1.414L10.586 12L8.293 9.707a.999.999 0 1 1 1.414-1.414L12 10.586l2.293-2.293a.999.999 0 1 1 1.414 1.414L13.414 12z"/>
              </svg>
            </span>`;
        const val = settings.value;
        mapDiv.addEventListener('click', () => {
          const value1 = settings.data.mobileNumber;
          handleMap(value1);
        });
        editDiv.addEventListener('click', () => {
          const value1 = settings.data.mobileNumber;
          handleEdit(value1);
        });
        deleteDiv.addEventListener('click', () => {
          const value1 = settings.data.mobileNumber;
          handleDelete(value1);
        });
        const template = document.createElement('div');
        template.appendChild(mapDiv);
        template.appendChild(editDiv);
        template.appendChild(deleteDiv);

        settings.template = template;
      }
    }
  ];

  const handleDelete = async (mobileNumber) => {
    // console.log("Mobile Number to delete =>", mobileNumber);

    if (!mobileNumber) {
      Swal.fire("Error", "Invalid mobile number.", "error");
      return;
    }

    const result = await Swal.fire({
      title: `Delete ${mobileNumber}?`,
      text: "Are you sure you want to delete this franchise?",
      icon: "warning",
      showCancelButton: true,
      confirmButtonColor: "#d33",
      cancelButtonColor: "#3085d6",
      confirmButtonText: "Yes, delete it!"
    });

    if (!result.isConfirmed) return;

    try {
      await axios.delete(`${baseURL}${config.deleteFranchiseDetails}${mobileNumber}/`);
      await Swal.fire("Deleted!", "Franchisee has been deleted.", "success");

      // Refresh table after deletion
      fetchFranchisee();
    } catch (error) {
      console.error("Failed to delete franchisee:", error);
      Swal.fire("Error", "Failed to delete franchisee.", "error");
    }
  };

  const handleEdit = async (mobileNumber) => {
    try {
      const response = await axios.get(`${baseURL}${config.adminGetFranchiseDetails}${mobileNumber}/`);
      const franchiseeDetails = response.data;
      // console.log("Detail of that Franchisee is =>>", franchiseeDetails)
      // Set form values
      setAddFranchiseeForm({
        franchiseeName: franchiseeDetails.franchiseeName || "",
        state: franchiseeDetails.state || "",
        city: franchiseeDetails.city || "",
        pincode: franchiseeDetails.pincode || "",
        address: franchiseeDetails.address || "",
        email: franchiseeDetails.email || "",
        mobileNumber: franchiseeDetails.mobileNumber || "",
      });

      // Show modal
      // const modal = new bootstrap.Modal(document.getElementById("adduser"));
      // modal.show();
      setIsAddUserPopup(true)

    } catch (error) {
      console.error("Failed to fetch Franchisee Details", error);
      alert("Failed to fetch Franchisee Details");
    }
  };


  //click event listener for edit map delete icons to call handleEdit() or handleDelete()  handleEdit() with correct user ID.
  useEffect(() => {
    const table_Icon = document.querySelector('smart-table');
    if (!table_Icon) return;
    const handleClick = (event) => {
      const editBtn = event.target.closest('.edit-icon');
      const deleteBtn = event.target.closest('.delete-icon');
      const mapBtn = event.target.closest('.map-icon');

      if (mapBtn) {
        const mobileNumber = mapBtn.getAttribute('data-id');
        handleMap(mobileNumber);
      }

      if (editBtn) {
        const userId = editBtn.getAttribute('data-id');
        handleEdit(userId);
      }

      if (deleteBtn) {
        const userCodes = deleteBtn.getAttribute('data-id');
        handleDelete(userCodes);
      }
    };

    table_Icon.addEventListener('click', handleClick);
    return () => table_Icon.removeEventListener('click', handleClick); //  Clean up
  }, [franchiseeData]);



  //=========================== ( Data fetching UseEffect ) ================================       

  const fetchFranchisee = async () => {
    try {
      const response = await axios.get(`${baseURL}${config.getAllFranchiseDetails}`);

      const formatted = response.data.map((item, index) => ({
        sno: index + 1,
        franchiseeUID: item.franchiseeUID,
        franchiseeName: item.franchiseeName,
        email: item.email,
        mobileNumber: item.mobileNumber,
        address: item.address,
        city: item.city,
        state: item.state,
        pincode: item.pincode,
        action: `
          <div style="display:flex; gap:10px;">
            <span class="map-icon" data-id="${item.mobileNumber}" style="cursor:pointer;" title="Map">
              <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 576 512">
                <path fill="currentColor" d="m384 476.1l-192-54.9V35.9l192 54.9zm32-1.2V88.4l127.1-50.9c15.8-6.3 32.9 5.3 32.9 22.3v334.8c0 9.8-6 18.6-15.1 22.3L416 474.8zM15.1 95.1L160 37.2v386.5L32.9 474.5C17.1 480.8 0 469.2 0 452.2V117.4c0-9.8 6-18.6 15.1-22.3"/>
              </svg>
            </span>
            <span class="edit-icon" data-id="${item.mobileNumber}" style="cursor:pointer;" title="Edit">
              <svg xmlns="http://www.w3.org/2000/svg" width="28" height="28" viewBox="0 0 24 24">
                <path fill="currentColor" d="M3.548 20.938h16.9a.5.5 0 0 0 0-1h-16.9a.5.5 0 0 0 0 1M9.71 17.18a2.6 2.6 0 0 0 1.12-.65l9.54-9.54a1.75 1.75 0 0 0 0-2.47l-.94-.93a1.79 1.79 0 0 0-2.47 0l-9.54 9.53a2.5 2.5 0 0 0-.64 1.12L6.04 17a.74.74 0 0 0 .19.72a.77.77 0 0 0 .53.22Zm.41-1.36a1.47 1.47 0 0 1-.67.39l-.97.26l-1-1l.26-.97a1.5 1.5 0 0 1 .39-.67l.38-.37l1.99 1.99Zm1.09-1.08l-1.99-1.99l6.73-6.73l1.99 1.99Zm8.45-8.45L18.65 7.3l-1.99-1.99l1.01-1.02a.75.75 0 0 1 1.06 0l.93.94a.754.754 0 0 1 0 1.06"/>
              </svg>
            </span>
            <span class="delete-icon"  data-id="${item.mobileNumber}" style="cursor:pointer;" title="Delete">
              <svg xmlns="http://www.w3.org/2000/svg"  width="28" height="28" viewBox="0 0 24 24">
                <path fill="currentColor" d="M12 4c-4.419 0-8 3.582-8 8s3.581 8 8 8s8-3.582 8-8s-3.581-8-8-8m3.707 10.293a.999.999 0 1 1-1.414 1.414L12 13.414l-2.293 2.293a.997.997 0 0 1-1.414 0a1 1 0 0 1 0-1.414L10.586 12L8.293 9.707a.999.999 0 1 1 1.414-1.414L12 10.586l2.293-2.293a.999.999 0 1 1 1.414 1.414L13.414 12z"/>
              </svg>
            </span>
          </div>
        `
      }));

      setFranchiseeData(formatted);
    } catch (error) {
      console.error("Failed to fetch Franchisee Details", error);
    }
  };

  useEffect(() => {
    fetchFranchisee();
  }, []);


  // ============================= (Downloading CSV ) ===============================================

  const handleCsvBtnClick = () => {
    const exportColumns = columns.filter(col => !col.excludeFromExport); // Remove 'action' column from export
    const headers = exportColumns.map(col => col.label).join(',');        // Create CSV header

    const rows = franchiseeData.map(row =>                                     // Create CSV rows
      exportColumns.map(col => row[col.dataField]).join(',')
    );

    const csvContent = [headers, ...rows].join('\n');                     // Combine header and data

    // Download as CSV file
    const file = new Blob([csvContent], { type: 'text/csv' });           //  Use correct variable
    const a = document.createElement('a');
    a.href = URL.createObjectURL(file);
    a.download = 'Franchisee_Details.csv';
    a.click();
  };

  // ===============================================================================

  return (
    <>
      {/* <!--  BEGIN CONTENT AREA  --> */}
      <div id="content" className="main-content">
        <div className="layout-px-spacing">
          <div className="middle-content container-xxl p-0">
            <div className="card mt-3">
              <div className="card-body">
                <div className="row">
                  <div className="d-flex align-items-center justify-content-between mb-3">
                    <h5>Franchise Details</h5>
                    <div className="d-flex gap-2">
                      <a href="/admin/dashboard"
                        className="btn btn-primary"
                        onClick={(e) => handleNavClick(e, "/admin/dashboard")}>
                        <i className="fa fa-arrow-left me-2"></i> Back
                      </a>
                      <button className="btn btn-primary" onClick={() => setIsAddUserPopup(true)}><i className="fa fa-add me-2"></i> Add Franchise</button>
                    </div>
                  </div>

                  {/* ================= (Table) ================== */}

                  <div className="row">
                    <div className="col-xl-12 col-lg-12 col-sm-12  layout-spacing" style={{ overflowx: 'auto' }}>
                      <div className="statbox widget box box-shadow" >
                        <div className="widget-content widget-content-area" >
                          <span style={{ cursor: 'pointer' }} title="Download to CSV formate">
                            <svg xmlns="http://www.w3.org/2000/svg" width="34" height="34" viewBox="0 0 24 24"
                              onClick={handleCsvBtnClick} style={{ cursor: "pointer" }}>
                              <g fill="none" stroke="#0257a7" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.5" color="#0257a7">
                                <path d="M10.294 14.016C10.248 13.024 9.571 13 8.651 13C7.235 13 7 13.338 7 14.667v1.666C7 17.662 7.235 18 8.651 18c.92 0 1.598-.024 1.643-1.016M21 13l-1.463 3.912c-.272.725-.407 1.088-.622 1.088s-.35-.363-.622-1.088L16.83 13m-2.109 0h-.972c-.389 0-.583 0-.736.063c-.522.216-.515.724-.515 1.187s-.007.97.515 1.187c.153.063.347.063.736.063c.388 0 .583 0 .736.063c.522.216.515.724.515 1.187s.007.97-.515 1.187c-.153.063-.348.063-.736.063h-1.06" />
                                <path d="M15 22h-4.273c-3.26 0-4.892 0-6.024-.798a4.1 4.1 0 0 1-.855-.805C3 19.331 3 17.797 3 14.727v-2.545c0-2.963 0-4.445.469-5.628c.754-1.903 2.348-3.403 4.37-4.113C9.095 2 10.668 2 13.818 2c1.798 0 2.698 0 3.416.252c1.155.406 2.066 1.263 2.497 2.35C20 5.278 20 6.125 20 7.818V10" />
                                <path d="M3 12a3.333 3.333 0 0 1 3.333-3.333c.666 0 1.451.116 2.098-.057A1.67 1.67 0 0 0 9.61 7.43c.173-.647.057-1.432.057-2.098A3.333 3.333 0 0 1 13 2" />
                              </g>
                            </svg>
                          </span>
                          <style> {` .smart-table thead th { background-color:rgb(224, 238, 249) !important; font-size: 13px !important; font-weight: 600; color: #333; } `} </style>
                          <Table
                            // ref={tableRef}
                            id="table"
                            appearance={{ alternationStart: 0, alternationCount: 2 }}
                            dataExport={{ view: true, viewStart: 0, viewEnd: 20 }}
                            dataSource={franchiseeData}
                            paging={true}
                            pageIndex={0}
                            pageSize={10}
                            columns={columns}
                            freezeHeader={true}
                          ></Table>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* =================== ( Table End ) ============================ */}

                </div>
              </div>
            </div>

          </div>

        </div>



      </div>
      {/* <!--  END CONTENT AREA  --> */}



      {/*======================== <!-- Modal Container for Add User --> =============================*/}
      <div id="adduser" className="modal modal-lg animated zoomInUp custo-zoomInUp" role="dialog">
        <div className="modal-dialog">
          {/* <!-- Modal content--> */}
          <div className="modal-content" style={{ backgroundColor: 'white', color: 'black' }} >
            <div className="modal-header">
              <h5 className="modal-title">Add Franchise</h5>
              <button type="button" className="btn-close" data-bs-dismiss="modal" aria-label="Close" >
                {/* <svg aria-hidden="true" xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" className="feather feather-x"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg> */}
              </button>
            </div>
            <div className="modal-body">
              <div className="form" id="stores1">
                <div className="row">


                  <div className="col-md-6">
                    <div className="form-group">
                      <label htmlFor="franchiseeName">Franchise Name</label>
                      <input type="text" className="form-control mb-3" id="franchiseeName" placeholder="Franchisee name" name="franchiseeName" onChange={handleChange} value={addFranchiseeForm.franchiseeName} />
                    </div>
                  </div>

                  <div className="col-md-6">
                    <div className="form-group">
                      <label htmlFor="email">Email</label>
                      <input type="text" className="form-control mb-3" id="email" placeholder="email" name="email" onChange={handleChange} value={addFranchiseeForm.email} />
                    </div>
                  </div>

                  <div className="col-md-6">
                    <div className="form-group">
                      <label htmlFor="mobileNumber">Mobile Number</label>
                      <input type="number" className="form-control mb-3" id="mobileNumber" placeholder="mobile Number" name="mobileNumber" onChange={handleChange} value={addFranchiseeForm.mobileNumber} />
                    </div>
                  </div>

                  <div className="col-md-6">
                    <div className="form-group">
                      <label htmlFor="address">Address</label>
                      <input type="text" className="form-control mb-3" id="address" placeholder="Address" name="address" onChange={handleChange} value={addFranchiseeForm.address} />
                    </div>
                  </div>


                  <div className="col-md-6">
                    <div className="form-group">
                      <label htmlFor="city">City</label>
                      <input type="text" className="form-control mb-3" id="city" placeholder="city" name="city" onChange={handleChange} value={addFranchiseeForm.city} />
                    </div>
                  </div>

                  <div className="col-md-6">
                    <div className="form-group">
                      <label htmlFor="state">State</label>
                      <input type="text" className="form-control mb-3" name="state" onChange={handleChange} id="state" placeholder="state" value={addFranchiseeForm.state} />
                    </div>
                  </div>

                  <div className="col-md-6">
                    <div className="form-group">
                      <label htmlFor="pincode">Pincode</label>
                      <input type="number" className="form-control mb-3" name="pincode" onChange={handleChange} id="pincode" placeholder="pincode" value={addFranchiseeForm.pincode} />
                    </div>
                  </div>

                </div>

              </div>
            </div>
            <div className="modal-footer md-button">
              <button className="btn btn-light-dark" data-bs-dismiss="modal" >Cancel</button>
              <button type="button" onClick={handleSave} className="btn btn-primary">Save</button>
            </div>
          </div>
        </div>
      </div>

      {/*====================== Map User Model Container =========================== */}

      <Dialog
        open={isAddUserPopup}
        aria-labelledby="alert-dialog-title"
        aria-describedby="alert-dialog-description"
        sx={{
          ".MuiDialog-paper": {
            maxWidth: "55rem !important",
          },
        }}
      >
        <DialogTitle id="alert-dialog-title"
        >
          {isAddUserPopup? "Add Franchise":"Edit Franchisee"}
        </DialogTitle>
        <IconButton
          aria-label="close"
          onClick={() =>{ setIsAddUserPopup(false), handleClose()}}
          sx={(theme) => ({
            position: 'absolute',
            right: 8,
            top: 8,
            color: theme.palette.grey[500],
          })}
        >
          <CloseIcon />
        </IconButton>
        <DialogContent
          sx={{
            width: { xs: '80vw', sm: '80vw', md: '55rem' },
            minHeight: '20rem',
          }}
        >
          <>
            <Grid container spacing={2} justify="center">
              <Grid size={{ lg: 6, md: 6, xs: 12 }}>
                <div className="form-group">
                  <label htmlFor="franchiseeName">Franchise Name</label>
                  <input type="text" className="form-control mb-3" id="franchiseeName" placeholder="Franchisee name" name="franchiseeName" onChange={handleChange} value={addFranchiseeForm.franchiseeName} />
                </div>
              </Grid>
              <Grid size={{ lg: 6, md: 6, xs: 12 }}>
                <div className="form-group">
                  <label htmlFor="email">Email</label>
                  <input type="text" className="form-control mb-3" id="email" placeholder="email" name="email" onChange={handleChange} value={addFranchiseeForm.email} />
                </div>
              </Grid>
              <Grid size={{ lg: 6, md: 6, xs: 12 }}>
                <div className="form-group">
                  <label htmlFor="mobileNumber">Mobile Number</label>
                  <input type="number" className="form-control mb-3" id="mobileNumber" placeholder="mobile Number" name="mobileNumber" onChange={handleChange} value={addFranchiseeForm.mobileNumber} />
                </div>
              </Grid>
              <Grid size={{ lg: 6, md: 6, xs: 12 }}>
                <div className="form-group">
                  <label htmlFor="address">Address</label>
                  <input type="text" className="form-control mb-3" id="address" placeholder="Address" name="address" onChange={handleChange} value={addFranchiseeForm.address} />
                </div>
              </Grid>
              <Grid size={{ lg: 6, md: 6, xs: 12 }}>
                <div className="form-group">
                  <label htmlFor="city">City</label>
                  <input type="text" className="form-control mb-3" id="city" placeholder="city" name="city" onChange={handleChange} value={addFranchiseeForm.city} />
                </div>
              </Grid>
              <Grid size={{ lg: 6, md: 6, xs: 12 }}>
                <div className="form-group">
                  <label htmlFor="state">State</label>
                  <input type="text" className="form-control mb-3" name="state" onChange={handleChange} id="state" placeholder="state" value={addFranchiseeForm.state} />
                </div>
              </Grid>
              <Grid size={{ lg: 6, md: 6, xs: 12 }}>
                <div className="form-group">
                  <label htmlFor="pincode">Pincode</label>
                  <input type="number" className="form-control mb-3" name="pincode" onChange={handleChange} id="pincode" placeholder="pincode" value={addFranchiseeForm.pincode} />
                </div>
              </Grid>
            </Grid>
          </>

        </DialogContent>
        <DialogActions>
          <button className="btn btn-light-dark" onClick={() =>{ setIsAddUserPopup(false), handleClose()}} >Cancel</button>
          <button type="button" onClick={handleSave} className="btn btn-primary">Save</button>
        </DialogActions>
      </Dialog>

      <div id="mapuser" className="modal modal-lg animated zoomInUp custo-zoomInUp" role="dialog">
        <div className="modal-dialog" >
          {/* <!-- Modal content--> */}
          <div className="modal-content" style={{ backgroundColor: 'white', color: 'black' }} >
            <div className="modal-header">
              <h5 className="modal-title">Franchisee Vendor Mapping</h5>
              <button type="button" className="btn-close" data-bs-dismiss="modal" aria-label="Close" >
              </button>
            </div>
            <div className="modal-body">
              <div className="form" id="stores1">
                <div className="row">


                  <div className="col-md-6">
                    <div className="form-group">
                      <label htmlFor="franchiseeName">Franchise Name</label>
                      <input
                        type="text"
                        value={selectedfranchiseeName}
                        className="form-control"
                        readOnly
                      />
                    </div>
                  </div>

                  <div className="col-md-6">
                    <div className="form-group">
                      <label htmlFor="map-mobileNumber">Mobile Number</label>
                      <input
                        type="text"
                        maxLength={10}
                        value={mapMobileNumber}
                        className="form-control"
                        readOnly
                      />
                    </div>
                  </div>

                  <div className="col-md-6">
                    <div className="form-group">
                      <label htmlFor="display">Vendor Code</label><br />
                      {/* <select
                        id="vendorCode"
                        className="form-select"
                        placeholder="Select Vendor Codes"
                        value={selectedVendorCode}
                        onChange={(e) => setSelectedVendorCode(e.target.value)}
                      >
                        <option value="" disabled>Select Vendor Codes</option>
                        {vendorCodes.map((vendor) => (
                          <option key={vendor.vendorUID} value={vendor.vendorCode}>
                            {vendor.vendorCode}
                          </option>
                        ))}
                      </select> */}
                    {/* <MultiSelect
                        id="vendorCode"
                        value={selectedVendorCode || []}
                        onChange={(e) => setSelectedVendorCode(e.value)}
                        options={vendorCodes}
                        optionLabel="vendorCode"
                        optionValue="vendorCode"
                        placeholder="Select Vendor Codes"
                        filter
                        maxSelectedLabels={3}
                        className="w-full md:w-20rem"
                      /> */}

                    </div>
                  </div>
                </div>
              </div>
            </div>
            <div className="modal-footer md-button">
              <button className="btn btn-light-dark" data-bs-dismiss="modal" >Cancel</button>
              <button type="button" onClick={handleMapSave} className="btn btn-primary">Save</button>
            </div>
          </div>
        </div>
      </div>

      <Dialog
        open={isMappingPopup}
        aria-labelledby="alert-dialog-title"
        aria-describedby="alert-dialog-description"
        sx={{
          ".MuiDialog-paper": {
            maxWidth: "55rem !important",
          },
        }}>
        <DialogTitle id="alert-dialog-title" > Franchisee Vendor Mapping </DialogTitle>
        <IconButton
          aria-label="close"
          onClick={() => setIsMappingPopup(false)}
          sx={(theme) => ({
            position: 'absolute',
            right: 8,
            top: 8,
            color: theme.palette.grey[500],
          })} >
          <CloseIcon />
        </IconButton>
        <DialogContent sx={{ width: { xs: '80vw', sm: '80vw', md: '55rem' }, minHeight: '20rem', }} >
          <>
            <Grid container spacing={2} justify="center">
              <Grid size={{ lg: 6, md: 6, xs: 12 }}>
                <div className="form-group">
                  <label htmlFor="franchiseeName">Franchise Name</label>
                  <input
                    type="text"
                    value={selectedfranchiseeName}
                    className="form-control"
                    readOnly
                  />
                </div>
              </Grid>
              <Grid size={{ lg: 6, md: 6, xs: 12 }}>
                <div className="form-group">
                  <label htmlFor="map-mobileNumber">Mobile Number</label>
                  <input
                    type="text"
                    value={mapMobileNumber}
                    className="form-control"
                    readOnly
                  />
                </div>
              </Grid>
              <Grid size={{ lg: 6, md: 6, xs: 12 }}>
                <div className="form-group">
                  <label htmlFor="display">Vendor Code</label><br />
                  {/* <select
                    id="vendorCode"
                    className="form-select"
                    placeholder="Select Vendor Codes"
                    value={selectedVendorCode}
                    onChange={(e) => setSelectedVendorCode(e.target.value)}
                  >
                    <option value="" disabled>Select Vendor Codes</option>
                    {vendorCodes.map((vendor) => (
                      <option key={vendor.vendorUID} value={vendor.vendorCode}>
                        {vendor.vendorCode}
                      </option>
                    ))}
                  </select> */}
                    <MultiSelect
                        id="vendorCode"
                        value={selectedVendorCode || []}
                        onChange={(e) => setSelectedVendorCode(e.value)}
                        options={vendorCodes}
                        optionLabel="vendorCode"
                        optionValue="vendorCode"
                        placeholder="Select Vendor Codes"
                        filter
                        maxSelectedLabels={3}
                        className="w-full md:w-20rem"
                      />
                </div>
              </Grid>
            </Grid>
          </>

        </DialogContent>
        <DialogActions>
          {/* <Button size="md" type="button" variant="primary" onClick={handleMapSave}>
            Save
          </Button>
          <Button style={{ marginLeft: "10px" }} size="md" type="button" variant="inherit" onClick={() => setIsMappingPopup(false)}>
            Cancel
          </Button> */}
          <button className="btn btn-light-dark" onClick={() => {setIsMappingPopup(false),handleClose()}}>Cancel</button>
          <button type="button" onClick={handleMapSave} className="btn btn-primary">Save</button>
        </DialogActions>
      </Dialog>

    </>
  )
}

export default franchiseDetails

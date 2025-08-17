import axios from 'axios';
import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom';
import Table from 'smart-webcomponents-react/table';
import { toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import Swal from "sweetalert2";
import { baseURL } from '../base';
import { config } from '../config';
import { Dialog, DialogActions, DialogContent, DialogTitle, } from "@mui/material";
import IconButton from '@mui/material/IconButton';
import CloseIcon from '@mui/icons-material/Close';
import { Grid2 as Grid } from '@mui/material';

import Visibility from '@mui/icons-material/Visibility';
import VisibilityOff from '@mui/icons-material/VisibilityOff';

import { Formik, Form, Field, ErrorMessage } from 'formik';
import * as Yup from 'yup';


function user() {
    const navigate = useNavigate();
    const [isEditing, setIsEditing] = useState(false);
    const [isAddUserPopup, setIsAddUserPopup] = useState(false);
    const [userData, setUsereData] = useState([]);

    const [showPassword, setShowPassword] = useState(false);
    const [showConformPassword, setShowConformPassword] = useState(false);

    const [addUserForm, setAddUserForm] = useState({
        username: "",
        password: "",
        conformPassword: '',
        state: "",
        city: "",
        pincode: "",
        address: "",
        email: "",
        panno: "",
        userType: ""
    });

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

 
    const resetFormState = () => {
        setAddUserForm({
            username: "",
            password: "",
            address: "",
            city: "",
            state: "",
            pincode: "",
            email: "",
            panno: "",
            userType: ""
        });
    };

    //=========================( Save And Update Logics )=======================================

    const handleSave = async (addUserForm) => {
        const { username } = addUserForm

        try {
            // Edit logic
            if (isEditing) {
                console.log("isEditing at save",isEditing);
                //console.log("update query is running", isEditing)
                const response = await axios.patch(`${baseURL}${config.editUserdetails}${username}/`, addUserForm);
                if (response.data.code === 200) {
                    //console.log("response.data", response.data)
                    toast.success("User updated successfully!");
                    fetchUsers(); // details fetched to the table
                    resetFormState();// this will Clear input fields once data inserted successfully
                    setIsEditing(false); // editing state reset after update

                } else {
                    toast.error("Failed to update User Details.");
                }
                return;
            }


            // else do the save logic
            const response = await axios.post(`${baseURL}${config.adduserdetails}`, addUserForm);
            if (response.data.code === 200) {
                toast.success("User added successfully!");
                fetchUsers();// this will refresh the table and rerender the new data
                resetFormState();  // this will Clear input fields once data inserted successfully
                return response.data;
            } else {
                alert("Failed to add user. Please try again.");
            }
        } catch (error) {
            //console.error("Error saving user:", error);
            if (error.response) {
                //console.log("Backend error response:", error.response.data);
                toast.error(JSON.stringify(error.response.data.message));
            }
        }
    };

    // ===============================================================================

    const handleNavClick = (e, value) => {
        e.preventDefault();
        navigate(value);
    };

    // ========================== ( table Edit and Delete Button , column ) =================================


    const validationSchema = Yup.object().shape({ 
        username: Yup.string().trim().required("Username is required"),
        email: Yup.string()
            .trim()
            .matches(
                /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.(com|in)$/,
                "Email must contain @ and ends with .com or .in"
            ) .required("Email is required"),
            //password Check only in add user form
        ...(!isEditing && {
                password: Yup.string()
                    .trim()
                    .matches(
                        /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])(?!.*\s)[A-Za-z\d@$!%*?&]{8,}$/,
                        "Password must be 8 characters (least - 1 uppercase, 1 lowercase, 1 number, and 1 special character,No Space)"
                    ).required("Password is required"),
                conformPassword: Yup.string()
                    .trim()
                    .oneOf([Yup.ref('password'), null], "Passwords must match")
                    .required("Confirm Password is required"),
        }),
        state: Yup.string().trim().matches(/^[A-Za-z\s]+$/, "State must contain letters only")
            .required("State is required"),
        city: Yup.string().trim().matches(/^[A-Za-z\s]+$/, "City must contain letters only")
            .required("City is required"),
        pincode: Yup.string()
            .trim()
            .matches(/^\d+$/, "Pincode must be a number")
            .length(6, "Pincode must be exactly 6 digits")
            .required("Pincode is required"),
        address: Yup.string().trim().required("Address is required"),
        panno: Yup.string()
            .trim()
            .matches(/^[A-Z]{5}[0-9]{4}[A-Z]{1}$/, "Invalid PAN number (i.e ABCDE1234F)")
            .required("PAN number is required"),
        userType: Yup.string().required("User Type is required"),
    });


    const columns = [{
        label: 'S. No',
        dataField: 'sno',
        dataType: 'string',
        width: 60
    },
    {
        label: 'User Name',
        dataField: 'vendorCode',
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
        label: 'PinCode',
        dataField: 'pincode',
        dataType: 'number',
        width: 150
    },
    // {
    //     label: 'Password',
    //     dataField: 'password',
    //     dataType: 'string',
    //     width: 150
    // },
    {
        label: 'Pan Number',
        dataField: 'panno',
        dataType: 'string',
        width: 150
    },
    {
        label: 'User Type',
        dataField: 'usertype',
        dataType: 'string',
        width: 150

    },
    {
        label: 'Action', 
        // dataField: 'vendorUID',
        width: 150,
        formatFunction: (settings) => {
            const editDiv = document.createElement('span');
            editDiv.className = "downBtn";
            editDiv.style.margin = "10px";
            editDiv.innerHTML = ` <span  style="cursor:pointer;" title="Edit">
                            <svg xmlns="http://www.w3.org/2000/svg" width="28" height="28" viewBox="0 0 24 24">
                            <path fill="currentColor" d="M3.548 20.938h16.9a.5.5 0 0 0 0-1h-16.9a.5.5 0 0 0 0 1M9.71 17.18a2.6 2.6 0 0 0 1.12-.65l9.54-9.54a1.75 1.75 0 0 0 0-2.47l-.94-.93a1.79 1.79 0 0 0-2.47 0l-9.54 9.53a2.5 2.5 0 0 0-.64 1.12L6.04 17a.74.74 0 0 0 .19.72a.77.77 0 0 0 .53.22Zm.41-1.36a1.47 1.47 0 0 1-.67.39l-.97.26l-1-1l.26-.97a1.5 1.5 0 0 1 .39-.67l.38-.37l1.99 1.99Zm1.09-1.08l-1.99-1.99l6.73-6.73l1.99 1.99Zm8.45-8.45L18.65 7.3l-1.99-1.99l1.01-1.02a.75.75 0 0 1 1.06 0l.93.94a.754.754 0 0 1 0 1.06"/>
                            </svg>
                            </span>`;
            const deleteDiv = document.createElement('span');
            deleteDiv.className = "downBtn";
            deleteDiv.style.margin = "10px";
            deleteDiv.innerHTML = `  <span  style="cursor:pointer;" title="Delete">
                            <svg xmlns="http://www.w3.org/2000/svg"  width="28" height="28" viewBox="0 0 24 24">
                            <path fill="currentColor" d="M12 4c-4.419 0-8 3.582-8 8s3.581 8 8 8s8-3.582 8-8s-3.581-8-8-8m3.707 10.293a.999.999 0 1 1-1.414 1.414L12 13.414l-2.293 2.293a.997.997 0 0 1-1.414 0a1 1 0 0 1 0-1.414L10.586 12L8.293 9.707a.999.999 0 1 1 1.414-1.414L12 10.586l2.293-2.293a.999.999 0 1 1 1.414 1.414L13.414 12z"/>
                            </svg>
                        </span>`;
            const val = settings.value;
            editDiv.addEventListener('click', () => {
                const value1 = settings.data.vendorCode;
                handleEdit(value1);
            });
            deleteDiv.addEventListener('click', () => {
                const value1 = `${settings.data.vendorUID}|${settings.data.vendorCode}`;
                handleDelete(value1);
            });
            const template = document.createElement('div');
            template.appendChild(editDiv);
            template.appendChild(deleteDiv);
            settings.template = template;
        }

    },

    ];


    const handleEdit = async(vendorCode) => {
        setIsEditing(true);
        try {
            // console.log("isEditing at edit",isEditing);
            const response = await axios.get(`${baseURL}${config.getuserdetails}${vendorCode}/`);
            const userDetails = response.data;
            console.log("Fetched user details from api in edit:", userDetails);
            //console.log("Detail of the user to update are (handle Edit )=>>", userDetails)
            // Set form values
            setAddUserForm({
                username: userDetails.vendorCode || "",
                password: userDetails.password || "",
                state: userDetails.state || "",
                city: userDetails.city || "",
                pincode: userDetails.pincode || "",
                panno: userDetails.panno || "",
                address: userDetails.address || "",
                email: userDetails.email || "",
                userType: userDetails.usertype || ""
            });

            // Show modal
            // const modal = new bootstrap.Modal(document.getElementById("adduser"));
            // modal.show();
            setIsAddUserPopup(true)

        } catch (error) {
            //console.error("Failed to fetch user details", error);
            alert("Failed to fetch user details");
        }
    };


    // Debounced handleEdit
    
    // const debounce = (func, delay) => {
    //     let timeoutId;
    //     return (...args) => {
    //         clearTimeout(timeoutId);
    //         timeoutId = setTimeout(() => func(...args), delay);
    //     };
    // };

    // const handleEdit = debounce(async (vendorCode) => {
    //     setIsEditing(true);
    //     try {
    //         const response = await axios.get(`${baseURL}${config.getuserdetails}${vendorCode}/`);
    //         const userDetails = response.data;
    //         console.log("API Response userDetails:", userDetails);
    //         setAddUserForm({
    //             username: userDetails.vendorCode || "",
    //             password: userDetails.password || "",
    //             state: userDetails.state || "",
    //             city: userDetails.city || "",
    //             pincode: userDetails.pincode || "",
    //             panno: userDetails.panno || "",
    //             address: userDetails.address || "",
    //             email: userDetails.email || "",
    //             userType: userDetails.userType || userDetails.usertype || ""
    //         });
    //         setIsAddUserPopup(true);
    //     } catch (error) {
    //         console.error("Failed to fetch user details", error);
    //         alert("Failed to fetch user details");
    //     }
    // }, 300);

    // useEffect(() => {
    //   console.log("isEditing updated inside useeffect:", isEditing);
    // }, [isEditing]);


    const handleDelete = async (userCodes) => {
        const [vendorUID, vendorCode] = userCodes.split('|');
        //console.log("codes are=>>", vendorCode, vendorUID);

        if (!vendorUID || !vendorCode) {
            Swal.fire("Error", "Invalid user ID or vendor code.", "error");
            return;
        }

        // Using Sweet Alert
        const result = await Swal.fire({
            title: `Delete ${vendorCode}?`,
            text: "Are you sure you want to delete this franchise?",
            icon: "warning",
            showCancelButton: true,
            confirmButtonColor: "#d33",
            cancelButtonColor: "#3085d6",
            confirmButtonText: "Yes, delete it!"
        });

        if (!result.isConfirmed) return;

        try {
            await axios.delete(`${baseURL}${config.deleteUserdetails}${vendorUID}/${vendorCode}/`);
            await Swal.fire("Deleted!", "User has been deleted.", "success");

            // Refresh table after deletion
            fetchUsers();
        } catch (error) {
            //console.error("Failed to delete user:", error);
            Swal.fire("Error", "Failed to delete user.", "error");
        }
    };


    //click event listener for edit or delete icons to call handleEdit() or handleDelete() with correct user ID.
    useEffect(() => {
        const table_Icon = document.querySelector('smart-table');
        if (!table_Icon) return;
        const handleClick = (event) => {
            const editBtn = event.target.closest('.edit-icon');
            const deleteBtn = event.target.closest('.delete-icon');

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
    }, [userData]);


    //=========================== ( Data fetching UseEffect ) ================================       

    const fetchUsers = async () => {
        try {
            const response = await axios.get(`${baseURL}${config.getalluserDetails}`);
            const formatted = response.data.map((item, index) => ({
                sno: index + 1,
                vendorCode: item.vendorCode,
                vendorUID: item.vendorUID,
                password: item.password,
                email: item.email,
                city: item.city,
                state: item.state,
                pincode: item.pincode,
                panno: item.panno,
                usertype: item.usertype,
                address: item.address,
                action:
                    `
                    <div style="display:flex; gap:10px;">
                        <span class="edit-icon" data-id="${item.vendorCode}" style="cursor:pointer;" title="Edit">
                            <svg xmlns="http://www.w3.org/2000/svg" width="28" height="28" viewBox="0 0 24 24">
                            <path fill="currentColor" d="M3.548 20.938h16.9a.5.5 0 0 0 0-1h-16.9a.5.5 0 0 0 0 1M9.71 17.18a2.6 2.6 0 0 0 1.12-.65l9.54-9.54a1.75 1.75 0 0 0 0-2.47l-.94-.93a1.79 1.79 0 0 0-2.47 0l-9.54 9.53a2.5 2.5 0 0 0-.64 1.12L6.04 17a.74.74 0 0 0 .19.72a.77.77 0 0 0 .53.22Zm.41-1.36a1.47 1.47 0 0 1-.67.39l-.97.26l-1-1l.26-.97a1.5 1.5 0 0 1 .39-.67l.38-.37l1.99 1.99Zm1.09-1.08l-1.99-1.99l6.73-6.73l1.99 1.99Zm8.45-8.45L18.65 7.3l-1.99-1.99l1.01-1.02a.75.75 0 0 1 1.06 0l.93.94a.754.754 0 0 1 0 1.06"/>
                            </svg>
                        </span>
                        <span class="delete-icon"  data-id="${item.vendorUID}|${item.vendorCode}" style="cursor:pointer;" title="Delete">
                            <svg xmlns="http://www.w3.org/2000/svg"  width="28" height="28" viewBox="0 0 24 24">
                            <path fill="currentColor" d="M12 4c-4.419 0-8 3.582-8 8s3.581 8 8 8s8-3.582 8-8s-3.581-8-8-8m3.707 10.293a.999.999 0 1 1-1.414 1.414L12 13.414l-2.293 2.293a.997.997 0 0 1-1.414 0a1 1 0 0 1 0-1.414L10.586 12L8.293 9.707a.999.999 0 1 1 1.414-1.414L12 10.586l2.293-2.293a.999.999 0 1 1 1.414 1.414L13.414 12z"/>
                            </svg>
                        </span>
                    </div>
                    `
            }));
            setUsereData(formatted);
        } catch (error) {
            //console.error("Failed to fetch Users Details", error);
        }
    };

    useEffect(() => {
        fetchUsers();
    }, []);

    // ============================= (Downloading CSV ) ===============================================

    const handleCsvBtnClick = () => {
        const exportColumns = columns.filter(col => !col.excludeFromExport); // Remove 'action' column from export
        const headers = exportColumns.map(col => col.label).join(',');        // Create CSV header

        const rows = userData.map(row =>                                     // Create CSV rows
            exportColumns.map(col => row[col.dataField]).join(',')
        );

        const csvContent = [headers, ...rows].join('\n');                     // Combine header and data

        // Download as CSV file
        const file = new Blob([csvContent], { type: 'text/csv' });           //  Use correct variable
        const a = document.createElement('a');
        a.href = URL.createObjectURL(file);
        a.download = 'User_Details.csv';
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

                                    {/* ================= (Back and addUser Button) ================== */}

                                    <div className="d-flex align-items-center justify-content-between mb-3">
                                        <h5>User Details</h5>
                                        <div className="d-flex gap-2">
                                            <a href="/admin/dashboard"
                                                className="btn btn-primary"
                                                onClick={(e) => handleNavClick(e, "/admin/dashboard")}>
                                                <i className="fa fa-arrow-left me-2"></i> Back
                                            </a>
                                            <button className="btn btn-primary" onClick={() => setIsAddUserPopup(true)}><i className="fa fa-add me-2"></i> Add User</button>
                                        </div>
                                    </div>

                                    {/* ================= (Table) ================== */}

                                    <div className="row">
                                        <div className="col-xl-12 col-lg-12 col-sm-12  layout-spacing">
                                            <div className="statbox widget box box-shadow">
                                                <div className="widget-content widget-content-area">
                                                    <span style={{ cursor: 'pointer' }} title="Download to CSV formate">
                                                        <svg xmlns="http://www.w3.org/2000/svg" width="34" height="34" viewBox="0 0 24 24" onClick={handleCsvBtnClick} style={{ cursor: "pointer" }} >
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
                                                        appearance={appearance}
                                                        dataExport={dataExport}
                                                        dataSource={userData}
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


                                    {/* =================== ( Table End ) ============================ */}

                                </div>
                            </div>
                        </div>

                    </div>

                </div>

            </div>
            {/* <!--  END CONTENT AREA  --> */}


            {/*=====================(Modal content Start )============================ */}
  
            <Dialog
                open={isAddUserPopup}
                aria-labelledby="alert-dialog-title"
                aria-describedby="alert-dialog-description"
                sx={{ ".MuiDialog-paper": { maxWidth: "55rem !important", },
                }} >
            <DialogTitle id="alert-dialog-title">{isEditing ?"Edit User":"Add User"}</DialogTitle>

            <IconButton
                aria-label="close"
                onClick={() => setIsAddUserPopup(false)}
                sx={(theme) => ({ position: 'absolute', right: 8, top: 8, color: theme.palette.grey[500], })} >
            <CloseIcon />
        </IconButton>

            <DialogContent
            sx={{ width: { xs: '80vw', sm: '80vw', md: '55rem' }, minHeight: '20rem', }}>
                <Formik initialValues={addUserForm} 
                        enableReinitialize={true}
                        validationSchema={validationSchema} 
                        onSubmit={async(values) => { 
                            const { conformPassword, ...userData } = values; // Destructuring remove conformPassword
                            await handleSave(userData); 
                            setIsAddUserPopup(false)
                        }} >
                {({ errors, touched, isValid, dirty }) => (
                    // console.log("Formik State:", { isValid, dirty }),
                <Form noValidate>
                    <Grid container rowSpacing={0} columnSpacing={2} justify="center">
                        <Grid size={{ lg: 6, md: 6, xs: 12 }}>
                            <div className="form-group">
                                <label htmlFor="username">User Name</label>
                                <Field name="username" type="text" className="form-control mb-3"  id="profession" placeholder="User name"  readOnly={isEditing}/>
                                <ErrorMessage name="username" component="div" className="text-danger" />
                            </div>
                        </Grid>
                            <Grid size={{ lg: 6, md: 6, xs: 12 }}>
                            <div className="form-group">
                                <label htmlFor="email">Email ID</label>
                                <Field name="email">
                                    {({ field, form }) => (
                                        <input
                                        {...field}
                                        type="text"
                                        id="email"
                                        placeholder="email"
                                        className="form-control mb-3"
                                        value={field.value || ""}
                                        onChange={(e) =>
                                            form.setFieldValue("email", e.target.value.toLowerCase())
                                        }
                                        />
                                    )}
                                </Field>
                                <ErrorMessage name="email" component="div" className="text-danger" />
                            </div>
                        </Grid>
          {!isEditing && <Grid size={{ lg: 6, md: 6, xs: 12 }}>
                            <div className="form-group">
                                <label htmlFor="password">Password</label>
                                <div className="input-group mb-3">
                                    <Field name="password">
                                        {({ field }) => (
                                            <div style={{ position: 'relative', width: '100%' }}>
                                                <input
                                                    {...field} type={showPassword ? "text" : "password"}
                                                    className="form-control" 
                                                    id="password" 
                                                    placeholder="Enter Password" 
                                                    />
                                                <IconButton onClick={() => setShowPassword(prev => !prev)} style={{ position: 'absolute', right: 5, top: 5 }} >
                                                    {showPassword ? <VisibilityOff /> : <Visibility />}
                                                </IconButton>
                                            </div>
                                        )}
                                    </Field>
                                </div>
                                <ErrorMessage name="password" component="div" className="text-danger" />
                            </div>
                        </Grid> }
         {!isEditing && <Grid size={{ lg: 6, md: 6, xs: 12 }}>
                            <div className="form-group">
                                <label htmlFor="conformPassword">Conform Password</label>
                                <div className="input-group mb-3">
                                    <Field name="conformPassword">
                                        {({ field }) => (
                                            <div style={{ position: 'relative', width: '100%' }}>
                                                <input
                                                    {...field} type={showConformPassword ? "text" : "password"}
                                                    className="form-control" 
                                                    id="conformPassword" 
                                                    placeholder="Confirm Password" 
                                                    />
                                                    <IconButton onClick={() => setShowConformPassword(prev => !prev)} style={{ position: 'absolute', right: 5, top: 5 }} >
                                                    {showConformPassword ? <VisibilityOff  /> : <Visibility />}
                                                </IconButton>
                                            </div>
                                        )}
                                    </Field>
                               </div>  
                                <ErrorMessage name="conformPassword" component="div" className="text-danger" />
                            </div>
                        </Grid>}
                            
                        <Grid size={{ lg: 6, md: 6, xs: 12 }}>
                            <div className="form-group">
                                <label htmlFor="state">State</label>
                                <Field name="state" type="text" className="form-control mb-3"  id="state" placeholder="state"  />
                                <ErrorMessage name="state" component="div" className="text-danger" />
                            </div>
                        </Grid>
                        <Grid size={{ lg: 6, md: 6, xs: 12 }}>
                            <div className="form-group">
                                <label htmlFor="city">City</label>
                                <Field name="city" type="text" className="form-control mb-3"  id="city" placeholder="city" />
                                <ErrorMessage name="city" component="div" className="text-danger" />
                            </div>
                        </Grid>
                        <Grid size={{ lg: 6, md: 6, xs: 12 }}>
                            <div className="form-group">
                                <label htmlFor="pincode">Pincode</label>
                                <Field name="pincode" type="text" className="form-control mb-3"  id="pincode" placeholder="pincode" />
                                <ErrorMessage name="pincode" component="div" className="text-danger" />
                            </div>
                        </Grid>
                        <Grid size={{ lg: 6, md: 6, xs: 12 }}>
                            <div className="form-group">
                                <label htmlFor="address">Address</label>
                                <Field name="address" type="text" className="form-control mb-3"  id="address" placeholder="address"  />
                                <ErrorMessage name="address" component="div" className="text-danger" />
                            </div>
                        </Grid>
                        <Grid size={{ lg: 6, md: 6, xs: 12 }}>
                            <div className="form-group">
                                <label htmlFor="panno">Pan No.</label>
                                <Field name="panno">
                                        {({ field, form }) => (
                                            <input
                                            {...field}
                                            type="text"
                                            id="panno"
                                            placeholder="Enter Pan Number"
                                            className="form-control mb-3"
                                            value={field.value || ""}
                                            onChange={(e) =>
                                                form.setFieldValue("panno", e.target.value.toUpperCase())
                                            }
                                            />
                                        )}
                                </Field>
                                <ErrorMessage name="panno" component="div" className="text-danger" />
                            </div>
                        </Grid>
                        <Grid size={{ lg: 6, md: 6, xs: 12 }}>
                            <div className="form-group">
                                <label htmlFor="userType">User Type</label>
                                <Field as="select" className="form-select" name="userType">
                                    <option value="" >Select User Type</option>
                                    <option value="USER" >User</option>
                                    <option value="ADMIN">Admin</option>
                                </Field>
                                <ErrorMessage name="userType" component="div" className="text-danger" />
                            </div>
                        </Grid>
                        <Grid item xs={12}>
                            <DialogActions>
                                <button className="btn btn-light-dark" onClick={() => {resetFormState();setIsAddUserPopup(false)}}>Cancel</button>
                                <button type="submit" className="btn btn-primary" disabled={!isValid || !dirty}> Save</button>
                            </DialogActions>
                        </Grid>
                

                    </Grid>
                </Form>
                )}
                </Formik>
            </DialogContent>
        
            </Dialog>

            {/*=====================(Modal content End)============================ */}
        </>
    )
}
 
export default user
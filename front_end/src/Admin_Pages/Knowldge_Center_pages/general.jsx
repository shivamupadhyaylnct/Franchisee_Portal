import axios from 'axios';
import  { useEffect, useState } from 'react'
import { toast } from "react-toastify";
import 'react-toastify/dist/ReactToastify.css';

import { baseURL, base } from '../../base';
import { config } from '../../config';
import { Link } from 'react-router-dom';
import { Button } from '@mui/material';
import Table from 'smart-webcomponents-react/table';
import Swal from 'sweetalert2';


function general() {

  const [file,setFile]= useState(null); 
  const [fileDescription , SetFileDescription] = useState("");
  const [fileTag , setFileTag] = useState("")
  const fileType = ["PDF", "Word Document", "Excel Sheet", "Video"]
  const [selectedFileType, setSelectedFileType] = useState("");
  const [generalData, setGeneralData] = useState([]);

  const handleFileChange = (e) => {
    setFile(e.target.files[0]);
  };

  const handleChange = (event) => {
    const { name, value } = event.target; //Destructring
    if (name === 'selectedFileType') {
        setSelectedFileType(value);
    } else if (name ==="fileDescription"){
        SetFileDescription(value);
    } else if (name ==="fileTag"){
        setFileTag(value); 
    }
  };

//   ====================== (table Details) =====================================
  
const columns = [
  {
    label: 'S. No',
    dataField: 'sno', // This should be generated on the frontend as index+1
    dataType: 'string',
    width: 100
  },
  {
    label: 'File Name',
    dataField: 'file_name',
    dataType: 'string',
    width: 200
  },
  {
    label: 'File Type',
    dataField: 'file_type',
    dataType: 'string',
    width: 150
  },
  {
    label: 'Description',
    dataField: 'description',
    dataType: 'string',
    width: 300
  },
  {
    label: 'Tags',
    dataField: 'tags',
    dataType: 'string',
    width: 250
  },
  {
    label: 'Action',
    dataField: 'action',
    width: 100,
    formatFunction: (settings) => {
      const deleteDiv = document.createElement('span');
      deleteDiv.className = "downBtn";
      deleteDiv.style.margin = "10px";
      deleteDiv.innerHTML = `
        <span style="cursor:pointer;" title="Delete">
          <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24">
            <path fill="currentColor" d="M12 4c-4.419 0-8 3.582-8 8s3.581 8 8 8s8-3.582 8-8s-3.581-8-8-8m3.707 10.293a.999.999 0 1 1-1.414 1.414L12 13.414l-2.293 2.293a.997.997 0 0 1-1.414 0a1 1 0 0 1 0-1.414L10.586 12L8.293 9.707a.999.999 0 1 1 1.414-1.414L12 10.586l2.293-2.293a.999.999 0 1 1 1.414 1.414L13.414 12z"/>
          </svg>
        </span>`;
      
      deleteDiv.addEventListener('click', () => {
        const fileId = settings.data.id; // Use actual ID from backend
        const fileName = settings.data.file_name;
        console.log("data is ",settings.data)
        handleDelete(fileId,fileName);
      });

      const template = document.createElement('div');
      template.appendChild(deleteDiv);
      settings.template = template;
    }
  }
];

  const fetchTabledata = async () => {
    try {
      const response = await axios.get(`${baseURL}${config.getKnowledgeCenterGeneralFiles}`);
      const result = await response.data;

      if (result.code === 200 && result.data) {
        const rowsWithSno = result.data.map((item, index) => ({
          sno: index + 1,
          ...item,
        }));
        setGeneralData(rowsWithSno);
      } else {
        console.error("Failed to fetch data:", result.message);
      }
    } catch (error) {
      console.error("Error while fetching knowledge center data:", error);
    }
  };

useEffect(() => {
  fetchTabledata();
}, []);

  const handleDelete = async (file_id, fileName) => {
   console.log("handle delete clicked")
    if (!file_id) {
      Swal.fire("Invalid file ID.");
      return;
    }

    const result = await Swal.fire({
      title: `Delete ${fileName}?`,
      text: "Are you sure you want to delete this file?",
      icon: "warning",
      showCancelButton: true,
      confirmButtonColor: "#d33",
      cancelButtonColor: "#3085d6",
      confirmButtonText: "Yes, delete it!"
    });

    if (!result.isConfirmed) return;
      try {
        const response = await axios.delete(`${baseURL}${config.deleteKnowledgeCenterFile}${file_id}/`);
                        //  await Swal.fire("Deleted!", "File has been deleted.", "success");
          if (response.status === 200) {
            toast.success("File deleted successfully.");
            fetchTabledata(); // Refresh the table
          } else {
            toast.error("Failed to delete the file.");
          }
      } catch (error) {
        console.error("Failed to delete file:", error);
        toast.error("Something went wrong while deleting.");
      }
  };

  const handleSubmit = async () => {
  if (!selectedFileType) {
    toast.error("Please select a file type.");
    return;
  }
  if (!fileTag.trim()) {
    toast.error("Please enter File tags.");
    return;
  }
  if (!fileDescription.trim()) {
    toast.error("Please enter a description about the file.");
    return;
  }
  if (!file) {
    toast.error("Please select a file before submitting.");
    return;
  }

  const fileTagArray = fileTag
    .split(',')
    .map(tag => tag.trim())
    .filter(tag => tag !== '');

  const category = "general";
  const formData = new FormData();
  formData.append('file', file);                        // actual file
  formData.append('filename', file.name);               // file name
  formData.append('selectedFileType', selectedFileType); // file type
  formData.append('fileDescription', fileDescription);  // description
  formData.append('fileTags', JSON.stringify(fileTagArray)); // tags as JSON
  formData.append('category', category);                // hardcoded or dynamic

  // For debugging: show data going to backend
  console.log("Form Data Content:");
  for (let pair of formData.entries()) {
    console.log(`${pair[0]}:`, pair[1]);
  }

  try {
    const response = await axios.post(`${baseURL}${config.uploadKnowledgeCenterFile}`, formData);

    if (response.status === 200) {
      toast.success("File uploaded successfully");
      fetchTabledata();
      // Reset fields
      setSelectedFileType(""); setFileTag(""); SetFileDescription(""); setFile(null);
    } else {
      toast.error("Upload failed");
    }
  } catch (error) {
    console.error("Upload Error:", error);
    toast.error("Something went wrong during upload.");
  }
};


  return (
      <div id="content" className="main-content">
        <div className="layout-px-spacing1">

          <div className="middle-content container-xxl p-0">
            <div id="tabsSimple" className="col-xl-12 col-12 layout-spacing mt-3">
              
              <div className="statbox widget">
                  {/* ================= (Back and addUser Button) ================== */}
                  <div className="widget-header bg-light">
                    <div className="d-flex align-items-center justify-content-between ">
                        <h4 className="p-3" >General</h4>
                        <div className="d-flex gap-2 m-3">
                            <Link to="/admin/adminKnowledgeCenter">
                                <button className="btn btn-primary">
                                    <i className="fa fa-arrow-left me-2"></i> Back
                                </button>
                            </Link>
                        </div>
                    </div>
                    </div>
        {/* ======================================= */}
                    <div className="widget-content widget-content-area pt-0">
                     <div className="tab-content" id="pills-tabContent">
                      <div id="pills-profile-icon" role="tabpanel" aria-labelledby="pills-profile-icon-tab" tabIndex="0">
                        <div className="row p-3">
                          <div className="form border rounded p-3" style={{ border: "2px solid black" }}>
                            <div className="row">

                              <div className="col-md-4 mb-3">
                                <div className="form-group">
                                  <label htmlFor="CategoryTag">File Type</label>
                                  <select name="selectedFileType" 
                                          id="CategoryTag" 
                                          className="form-select" 
                                          value={selectedFileType}
                                          onChange={handleChange}>
                                      <option value="" disabled>Select the file Type</option>
                                      {fileType.map((option) => (
                                        <option key={option} value={option}>{option}</option>
                                      ))}
                                  </select>
                                </div>
                              </div>

                              <div className="col-md-4 mb-3">
                                <div className="form-group">
                                  <label htmlFor="fileTag" className="form-label">Tags</label>
                                  <input type="text"
                                          id="fileTag"
                                          style={{ color: "black" }}
                                          name="fileTag"
                                          className="form-control"
                                          placeholder="Tags separated by commas (policy, returns, exchange)"
                                          value={fileTag}
                                          onChange={handleChange}
                                  />
                                </div>
                              </div>

                              <div className="col-md-4 mb-3">
                                  <div className="form-group">
                                      <label htmlFor="fileDescription">Description</label>
                                          <textarea
                                          name="fileDescription"
                                          id="description"
                                          style={{ color: "black" }}
                                          className="form-control"
                                          value={fileDescription}
                                          onChange={handleChange}
                                          placeholder="Description About the file"
                                          rows={4}
                                          ></textarea>
                                  </div>
                              </div>

                               <div className="col-md-4 mt-2 mb-3">
                                <div className="form-group">
                                  <label htmlFor="file-upload">Choose file </label> <br/>
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
                                    <span> <b>{file ? file.name : ''}</b></span>
                                </div>
                              </div>

                               <div className="d-flex justify-content-end mt-4">
                                    <Button onClick={handleSubmit} 
                                            variant="contained" 
                                            color="primary">
                                      Submit File
                                    </Button>
                                </div>

                            </div>
                          </div>
                        </div>

                      </div>
                {/* ================= (Table Start) ================== */}
                    <div className="row mt-4">
                    <div className="col-xl-12 col-lg-12 col-sm-12  layout-spacing" style={{ overflowX: 'auto' }}>
                        <div className="statbox widget box box-shadow" >
                        <div className="widget-content widget-content-area" >
                            <style> {` .smart-table thead th { background-color:rgb(224, 238, 249) !important; font-size: 13px !important; font-weight: 600; color: #333; } `} </style>
                                <Table
                                id="table"
                                appearance={{ alternationStart: 0, alternationCount: 2 }}
                                dataExport={{ view: true, viewStart: 0, viewEnd: 20 }}
                                dataSource={generalData}
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
                {/* ==================================== */}
              </div>
            </div>
          </div>
        </div>
      </div>
  )
}

export default general;

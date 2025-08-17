import axios from "axios";
import { useEffect, useState } from "react";
import "react-toastify/dist/ReactToastify.css";
import { base } from "../../base";
import { baseURL } from "../../base";
import { config } from "../../config";
import { Link } from "react-router-dom";
import Table from "smart-webcomponents-react/table";

function userTraining() {
const [generalData, setGeneralData] = useState([]);

  const columns = [
    {
      label: "S. No",
      dataField: "sno",
      dataType: "string",
      width: 100,
    },
    {
      label: "File Name",
      dataField: "file_name",
      dataType: "string",
      width: 200,
    },
    {
      label: "File Type",
      dataField: "file_type",
      dataType: "string",
      width: 150,
    },
    {
      label: "Description",
      dataField: "description",
      dataType: "string",
      width: 300,
    },
    {
      label: "Download",
      dataField: "file_name", // raw file URL from backend
      dataType: "string",
      width: 150,
      formatFunction: (settings) => {
        const category = settings.data.category; // pick from row
        const filename = settings.value;
        const fileUrl = `${base}media/knowledge-center/${category}/${filename}`;
        // console.log("Download link: ", fileUrl);
        // const fileUrl = `C:\MG_Portal\App_Data\knowledge_center\general\dummy.pdf`;
        settings.template = `
        <a href="${fileUrl}" target="_blank" download class="btn btn-sm btn-primary">
          Download
        </a>
      `;
      },
    },
  ];

  const fetchTabledata = async () => {
    try {
      const response = await axios.get( `${baseURL}${config.getKnowledgeCenterTrainingFiles}` );
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

  return (
       <div id="content" className="main-content">
         <div className="layout-px-spacing1">
           <div className="middle-content container-xxl p-0">
             <div id="tabsSimple" className="col-xl-12 col-12 layout-spacing mt-3">
               <div className="statbox widget">
                 {/* ================= (Back and addUser Button) ================== */}
   
                 <div className="box box-shadow d-flex align-items-center justify-content-between ">
                   <h4 className="p-3">Training Module</h4>
                   <div className="d-flex gap-2 m-3">
                     <Link to="/user/knowledgecenter">
                       <button className="btn btn-primary">
                         <i className="fa fa-arrow-left me-2"></i> Back
                       </button>
                     </Link>
                   </div>
                 </div>
   
                 {/* ======================================= */}
                 <div className="widget-content widget-content-area pt-0">
                   <div className="tab-content" id="pills-tabContent">

                     <div className="row mt-4">
                       <div
                         className="col-xl-12 col-lg-12 col-sm-12  layout-spacing"
                         style={{ overflowX: "auto" }}
                       >
                         <div className="statbox widget box box-shadow">
                           <div className="widget-content widget-content-area">
                             <style>
                               {" "}
                               {` .smart-table thead th { background-color:rgb(224, 238, 249) !important; font-size: 13px !important; font-weight: 600; color: #333; } `}{" "}
                             </style>
                             <Table
                               id="table"
                               appearance={{
                                 alternationStart: 0,
                                 alternationCount: 2,
                               }}
                               dataExport={{
                                 view: true,
                                 viewStart: 0,
                                 viewEnd: 20,
                               }}
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

export default userTraining

import axios from "axios";
import { useEffect, useState } from "react";
import "react-toastify/dist/ReactToastify.css";
import { base } from "../../base";
import { baseURL } from "../../base";
import { config } from "../../config";
import { Link } from "react-router-dom";
import Table from "smart-webcomponents-react/table";

function userGeneral() {
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
    //   {
    //     label: 'Tags',
    //     dataField: 'tags',
    //     dataType: 'string',
    //     width: 250
    //   },
    //   {
    //     label: 'Action',
    //     dataField: 'action',
    //     width: 100,
    //     formatFunction: (settings) => {
    //       const deleteDiv = document.createElement('span');
    //       deleteDiv.className = "downBtn";
    //       deleteDiv.style.margin = "10px";
    //       deleteDiv.innerHTML = `
    //         <span style="cursor:pointer;" title="Delete">
    //           <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24">
    //             <path fill="currentColor" d="M12 4c-4.419 0-8 3.582-8 8s3.581 8 8 8s8-3.582 8-8s-3.581-8-8-8m3.707 10.293a.999.999 0 1 1-1.414 1.414L12 13.414l-2.293 2.293a.997.997 0 0 1-1.414 0a1 1 0 0 1 0-1.414L10.586 12L8.293 9.707a.999.999 0 1 1 1.414-1.414L12 10.586l2.293-2.293a.999.999 0 1 1 1.414 1.414L13.414 12z"/>
    //           </svg>
    //         </span>`;

    //       deleteDiv.addEventListener('click', () => {
    //         const fileId = settings.data.id; // Use actual ID from backend
    //         handleDelete(fileId);
    //       });

    //       const template = document.createElement('div');
    //       template.appendChild(deleteDiv);
    //       settings.template = template;
    //     }
    //   }
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
      const response = await axios.get( `${baseURL}${config.getKnowledgeCenterGeneralFiles}` );
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
                <h4 className="p-3">General</h4>
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

                  {/* ================= (Table Start) ================== */}
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
  );
}

export default userGeneral;

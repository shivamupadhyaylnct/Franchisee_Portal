
import { useLocation, Link } from "react-router-dom";
import Table from "smart-webcomponents-react/table";
import { base } from "../../base";
function UserSearchResult() {
  const location = useLocation();
  const data = location.state?.resultData || [];

  const columns = [
    { 
        label: "S. No",
        dataField: "sno", 
        dataType: "string", 
        width: 100 
    },
    { 
        label: "File Name", 
        dataField: "file_name", 
        dataType: "string", 
        width: 150 
    },
    { 
        label: "File Type",
        dataField: "file_type", 
        dataType: "string", 
        width: 150 
    },
     { 
        label: "File Category",
        dataField: "category", 
        dataType: "string", 
        width: 200 
    },
    { 
        label: "Description", 
        dataField: "description", 
        dataType: "string", 
        width: 300 
    },
    {
      label: "Download",
      dataField: "file_name",
      dataType: "string",
      width: 150,
      formatFunction: (settings) => {
        const category = settings.data.category;
        const filename = settings.value;
        const fileUrl = `${base}media/knowledge-center/${category}/${filename}`;
        settings.template = `
          <a href="${fileUrl}" target="_blank" download class="btn btn-sm btn-primary">
            Download
          </a>
        `;
      },
    },
  ];

  return (
    <div id="content" className="main-content">
      <div className="layout-px-spacing1">
        <div className="middle-content container-xxl p-0">
          <div className="statbox widget mt-3">
            <div className="box box-shadow d-flex align-items-center justify-content-between">
              <h4 className="p-3">Search Results</h4>
              <Link to="/user/knowledgecenter">
                <button className="btn btn-primary m-3">
                  <i className="fa fa-arrow-left me-2"></i> Back
                </button>
              </Link>
            </div>

            <div className="widget-content widget-content-area pt-0">
              <div className="tab-content" id="pills-tabContent">
                <div className="row mt-4">
                  <div
                    className="col-xl-12 layout-spacing"
                    style={{ overflowX: "auto" }}
                  >
                    <Table
                      dataSource={data}
                      paging={true}
                      pageIndex={0}
                      pageSize={10}
                      columns={columns}
                      freezeHeader={true}
                    />
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div> 
    </div>
  );
}

export default UserSearchResult;

import axios from "axios";
import { useEffect, useState } from "react";
import "react-toastify/dist/ReactToastify.css";
import { useNavigate } from "react-router-dom";
import { baseURL } from "../base";
import { config } from "../config";
import { Link } from "react-router-dom";

function KnowledgeCenter() {
  const navigate = useNavigate();
  const [searchTerm, setSearchTerm] = useState("");
  const [suggestion, setSuggestion] = useState([]); //Array of string
  const [selectedSuggetion, setSelectedSuggetion] = useState([]);
  const [selectedTermSet, setSelectedTermSet] = useState(new Set()); //Skip Suggestion if already Selected

  //=================( Fetching files to suggest)====================================

  useEffect(() => {
    const fetchFileSuggestion = async () => {
      if (searchTerm.trim() === "") {
        setSuggestion([]);
        return;
      }
      try {
        const response = await axios.get( `${baseURL}admin/getFileSearchSuggestions/?query=${searchTerm}` );

        if (response.data.code === 200) {
          setSuggestion(response.data.data); // flat string list
        }
      } catch (error) {
        console.log("error while fetching data : ", error);
      }
    };
    fetchFileSuggestion();
  }, [searchTerm]);

  //===================================================================================

  const handleSelectSaearchTerm = (Term) => {
    setSelectedSuggetion([...selectedSuggetion, Term]); // add to pills
    setSelectedTermSet(new Set([...selectedTermSet, Term.id])); // store ID
    setSelectedSuggetion([...selectedSuggetion, Term]); // clear search input box
    setSelectedTermSet(new Set([...selectedTermSet, Term])); // hide Dropdown of suggestion
  };

  const handndleRemoveSerchTerm = (Term) => {
    // 1. Filter out the removed term from selected suggestions
    const updatedSuggestion = selectedSuggetion.filter((item) => item !== Term); // remove the selecetd id
    setSelectedSuggetion(updatedSuggestion);

    // 2. Remove it from selected ID set
    const update = new Set(selectedTermSet);
    update.delete(Term);
    setSelectedTermSet(update);

    // 3. Reset table when all tags removed
    if (update.length === 0) {
      fetchTabledata();
    }
  };
  console.log("suggestion sre :", selectedSuggetion);

  // =======================================================================================

  const handleSearchSubmit = async () => {
    if (selectedSuggetion.length === 0) {
      fetchTabledata(); // fallback
      return;
    }

    try {
      //  const response = await axios.post( "http://localhost:8000/api/admin/searchFilesByTerms/", selectedSuggetion );
       const response = await axios.post( `${baseURL}${config.searchFilesByTerms}`, selectedSuggetion );

      if (response.data.code === 200) {
        const rowsWithSno = response.data.data.map((item, index) => ({
          sno: index + 1,
          ...item,
        }));
        console.log("RESPONSE DATA : ",rowsWithSno)
      
          // Navigate and pass data to search result page
        navigate("/user/knowledgecenter/userSearchResult", { state: { resultData: rowsWithSno }, });
        setSelectedSuggetion([]);
        setSelectedTermSet(new Set());
      } else {
        console.error("Search API failed:", response.data.message);
      }
    } catch (error) {
      console.error("Error during search:", error);
    }
  };

  return (
    <div id="content" className="main-content">
      <div className="layout-px-spacing1">
        <div className="middle-content container-fluid px-5">
          <div className="card mt-3">
            <div className="card-body">
              <div className="card">
                <div className="card-body">
                  <div className="d-flex align-items-center justify-content-between">
                    <h4>Knowledge Center</h4>
                    <div className="d-flex gap-2">
                      <Link to="/user/dashboard" className="btn btn-primary">
                        <i className="fa fa-arrow-left me-2"></i> Back
                      </Link>
                    </div>
                  </div>
                </div>
              </div>

              <div className="fq-header-wrapper">
                <div className="container">
                  <div className="row">
                    <div className="col-md-12 align-self-center order-md-0 order-1">
                      <div id="pills-profile-icon" role="tabpanel" aria-labelledby="pills-profile-icon-tab" tabIndex="0" >
                        <div className="fq-header-wrapper">
                          <div className="container">
                            <div className="row">
                              <div className="col-md-12 align-self-center order-md-0 order-1">
                                <div className="faq-header-content">
                                  <div className="row">
                                    {/* <label forHtml="search">Search for the fileName Tags or Description</label> */}
                                    <div className="col-lg-5 mx-auto">
                                      <div className="autocomplete-btn">
                                        {/* Container for pills and input */}
                                        <div className="input-with-pills">
                                          {selectedSuggetion.map((Term) => (
                                            <span key={Term} 
                                                  className="user-pill" 
                                                  onClick={() => handndleRemoveSerchTerm(Term) } >
                                              <span>{Term} &times;</span>
                                            </span>
                                          ))}
                                          <input
                                            id="search"
                                            style={{ color: "black" }}
                                            className="search-input"
                                            value={searchTerm}
                                            onChange={(e) =>
                                              setSearchTerm(e.target.value)
                                            }
                                            placeholder="Search by tag, file name, type, etc"
                                          />
                                        </div>

                                        <div className="search-btn-wrapper">
                                          <button className="btn btn-primary" onClick={handleSearchSubmit} > Search </button>
                                        </div>

                                        {/* Display Suggestions Dropdown */}
                                        {searchTerm.trim() !== "" &&
                                          suggestion.length > 0 && (
                                            <ul className="suggestions-list">
                                              {suggestion.map((Term) =>
                                                !selectedTermSet.has(Term) ? (
                                                  <li
                                                    key={Term}
                                                    onClick={() =>
                                                      handleSelectSaearchTerm(
                                                        Term
                                                      )
                                                    }
                                                  >
                                                    <span>{Term}</span>
                                                  </li>
                                                ) : null
                                              )}
                                            </ul>
                                          )}
                                      </div>
                                    </div>
                                  </div>
                                  <p className="mt-4 mb-0">
                                    {" "}
                                    Search with the Tag or File Name{" "}
                                  </p>
                                </div>
                              </div>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              <div className="faq container">
                <div className="faq-layouting layout-spacing">
                  <div className="kb-widget-section">
                    <div className="row justify-content-center">
                      <div className="col-12 col-sm-6 col-md-4 col-lg-3">
                        <Link to="/user/knowledgecenter/userGeneral">
                          <div className="card">
                            <div className="card-body">
                              <div className="card-icon mb-4">
                                <svg
                                  xmlns="http://www.w3.org/2000/svg"
                                  width="24"
                                  height="24"
                                  viewBox="0 0 24 24"
                                  fill="none"
                                  stroke="currentColor"
                                  stroke-width="2"
                                  stroke-linecap="round"
                                  stroke-linejoin="round"
                                  className="feather feather-airplay"
                                >
                                  <path d="M5 17H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2h-1"></path>
                                  <polygon points="12 15 17 21 7 21 12 15"></polygon>
                                </svg>
                              </div>
                              <h5 className="card-title mb-0">General</h5>
                            </div>
                          </div>
                        </Link>
                      </div>

                      <div className="col-12 col-sm-6 col-md-4 col-lg-3">
                        <Link to="/user/knowledgecenter/userSOP">
                          <div className="card">
                            <div className="card-body">
                              <div className="card-icon mb-4">
                                <svg
                                  xmlns="http://www.w3.org/2000/svg"
                                  width="24"
                                  height="24"
                                  viewBox="0 0 24 24"
                                  fill="none"
                                  stroke="currentColor"
                                  stroke-width="2"
                                  stroke-linecap="round"
                                  stroke-linejoin="round"
                                  className="feather feather-user"
                                >
                                  <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
                                  <circle cx="12" cy="7" r="4"></circle>
                                </svg>
                              </div>
                              <h5 className="card-title mb-0">SOP</h5>
                            </div>
                          </div>
                        </Link>
                      </div>

                      <div className="col-12 col-sm-6 col-md-4 col-lg-3">
                        <Link to="/user/knowledgecenter/userTraining">
                          <div className="card">
                            <div className="card-body">
                              <div className="card-icon mb-4">
                                <svg
                                  xmlns="http://www.w3.org/2000/svg"
                                  width="24"
                                  height="24"
                                  viewBox="0 0 24 24"
                                  fill="none"
                                  stroke="currentColor"
                                  stroke-width="2"
                                  stroke-linecap="round"
                                  stroke-linejoin="round"
                                  className="feather feather-package"
                                >
                                  <line
                                    x1="16.5"
                                    y1="9.4"
                                    x2="7.5"
                                    y2="4.21"
                                  ></line>
                                  <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"></path>
                                  <polyline points="3.27 6.96 12 12.01 20.73 6.96"></polyline>
                                  <line
                                    x1="12"
                                    y1="22.08"
                                    x2="12"
                                    y2="12"
                                  ></line>
                                </svg>
                              </div>
                              <h5 className="card-title mb-0">
                                Training Modules
                              </h5>
                            </div>
                          </div>
                        </Link>
                      </div>

                      <div className="col-12 col-sm-6 col-md-4 col-lg-3">
                        <Link to="/user/knowledgecenter/userFranchisee">
                          <div className="card">
                            <div className="card-body">
                              <div className="card-icon mb-4">
                                <svg
                                  xmlns="http://www.w3.org/2000/svg"
                                  width="24"
                                  height="24"
                                  viewBox="0 0 24 24"
                                  fill="none"
                                  stroke="currentColor"
                                  stroke-width="2"
                                  stroke-linecap="round"
                                  stroke-linejoin="round"
                                  className="feather feather-dollar-sign"
                                >
                                  <line x1="12" y1="1" x2="12" y2="23"></line>
                                  <path d="M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"></path>
                                </svg>
                              </div>
                              <h5 className="card-title mb-0">
                                {" "}
                                Franchisee Helpbooks{" "}
                              </h5>
                            </div>
                          </div>
                        </Link>
                      </div>
                    </div>
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

export default KnowledgeCenter;

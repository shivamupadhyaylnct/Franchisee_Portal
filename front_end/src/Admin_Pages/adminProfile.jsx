import axios from 'axios';
import React, { useEffect, useState } from 'react'
import { toast } from 'react-toastify';
import { baseURL } from '../base';
import { config } from '../config';

function adminProfile() {
    const user = localStorage.getItem("user_details");
    const userDetails = JSON.parse(user)
    const vendorCodes = userDetails.map(u => u.UserName);

    const [selectedVendor, setSelectedVendor] = useState('');
    const [franchiseeDetails, setFranchiseeDetails] = useState(null);


    const handleVendorCodeChange = (event) => {
        setSelectedVendor(event.target.value);
    };

    // Set first vendor as default on mount
    useEffect(() => {
        if (selectedVendor === "") {
            setSelectedVendor(vendorCodes[0])
        }
    }, [selectedVendor]);

    // Fetch franchisee details when selectedVendor changes
    useEffect(() => {
        // console.log(selectedVendor,"useEffect is running with vendor code ")
        const fetchFranchiseeDetails = async (event) => {
            if (!selectedVendor) return;

            try {
                const response = await axios.post(`${baseURL}${config.getFranchiseDetails}`, {
                    selectedVendorCode: selectedVendor
                });

                if (response.data.code === 200 && response.data.vendor_details?.WA_FRNCHSE) {
                    setFranchiseeDetails(response.data.vendor_details.WA_FRNCHSE);
                } else {
                    setFranchiseeDetails(null);
                }
            } catch (error) {
                toast.error("Error fetching vendor details:", error);
                setFranchiseeDetails(null);
            }
        };
        fetchFranchiseeDetails();
    }, [selectedVendor]);

    //===============================================================

    return (
        <>
            <div id="content" className="main-content" >
                <div className="layout-px-spacing"  >
                    <div className="middle-content container-xxl p-0 mt-3" style={{ backgroundColor: 'white', color: 'black' }} >
                        <div className="col-xl-12 col-lg-12 col-md-12 layout-spacing">
                            <form className="section general-info" >
                                <div className="info" >
                                    <h3 className="inv-title mb-2 pb-3 pt-3" >Profile Information</h3>
                                    <div className="row">
                                        <div className="col-lg-12 mx-auto">
                                            <div className="row">
                                                <div className="col-xl-12 col-lg-12 col-md-12 mt-md-0 mt-4">
                                                    <div className="form">
                                                        <div className="row">
                                                            <div className="col-md-3">
                                                                <div className="form-group">
                                                                    <label for="country">Vendor Code</label>
                                                                    <select
                                                                        name="selectvendor"
                                                                        id="selectvendor"
                                                                        className="form-select mb-3"
                                                                        style={{ width: '215px' }}
                                                                        value={selectedVendor}
                                                                        onChange={handleVendorCodeChange}
                                                                    >
                                                                        <option disabled>Select Vendor Code</option>
                                                                        {vendorCodes.map((option) => (
                                                                            <option key={option} value={option}>{option}</option>
                                                                        ))}
                                                                    </select>
                                                                </div>
                                                            </div>
                                                        </div>
                                                        {/* Profile Details Section */}
                                                        {franchiseeDetails && (
                                                            <div className="row">
                                                                <div className="col-md-4 mb-3">
                                                                    <div className="form-group">
                                                                        <label>Name Of Vendor</label>
                                                                        <div className="fake-input">{franchiseeDetails.NAME1}</div>
                                                                    </div>
                                                                </div>

                                                                <div className="col-md-4 mb-3">
                                                                    <div className="form-group">
                                                                        <label>PAN No</label>
                                                                        <div className="fake-input">{franchiseeDetails.J_1IPANNO}</div>
                                                                    </div>
                                                                </div>

                                                                <div className="col-md-4 mb-3">
                                                                    <div className="form-group">
                                                                        <label>Address 1</label>
                                                                        <div className="fake-input">{franchiseeDetails.HOUSE_NUM1}</div>
                                                                    </div>
                                                                </div>

                                                                <div className="col-md-4 mb-3">
                                                                    <div className="form-group">
                                                                        <label>Address 2</label>
                                                                        <div className="fake-input">{franchiseeDetails.STREET}</div>
                                                                    </div>
                                                                </div>

                                                                <div className="col-md-4 mb-3">
                                                                    <div className="form-group">
                                                                        <label>City</label>
                                                                        <div className="fake-input">{franchiseeDetails.CITY1}</div>
                                                                    </div>
                                                                </div>

                                                                <div className="col-md-4 mb-3">
                                                                    <div className="form-group">
                                                                        <label>Postal Code</label>
                                                                        <div className="fake-input">{franchiseeDetails.POST_CODE1}</div>
                                                                    </div>
                                                                </div>

                                                                <div className="col-md-4 mb-3">
                                                                    <div className="form-group">
                                                                        <label>Country</label>
                                                                        <div className="fake-input">{franchiseeDetails.LANDX}</div>
                                                                    </div>
                                                                </div>

                                                                <div className="col-md-4 mb-3">
                                                                    <div className="form-group">
                                                                        <label>Telephone</label>
                                                                        <div className="fake-input">{franchiseeDetails.TEL_NUMBER}</div>
                                                                    </div>
                                                                </div>

                                                                <div className="col-md-4 mb-3">
                                                                    <div className="form-group">
                                                                        <label>Email ID</label>
                                                                        <div className="fake-input">{franchiseeDetails.SMTP_ADDR}</div>
                                                                    </div>
                                                                </div>

                                                                <div className="col-md-4 mb-3">
                                                                    <div className="form-group">
                                                                        <label>GST No</label>
                                                                        <div className="fake-input">{franchiseeDetails.STCD3}</div>
                                                                    </div>
                                                                </div>

                                                                <div className="col-md-4 mb-3">
                                                                    <div className="form-group">
                                                                        <label>Bank Name</label>
                                                                        <div className="fake-input">{franchiseeDetails.BANKA}</div>
                                                                    </div>
                                                                </div>

                                                                <div className="col-md-4 mb-3">
                                                                    <div className="form-group">
                                                                        <label>Bank Account No./ IFSC Code</label>
                                                                        <div className="fake-input">
                                                                            {franchiseeDetails.BANKN} / {franchiseeDetails.IFSC}
                                                                        </div>
                                                                    </div>
                                                                </div>
                                                            </div>
                                                        )}


                                                        {/* <div className="row">
                                                    <div className="col-md-4 mb-3">
                                                        <div className="form-group">
                                                            <label for="fullName">Name Of Franchisee</label>
                                                            <div className="fake-input">hello</div>
                                                        </div>
                                                    </div>

                                                    <div className="col-md-4 mb-3">
                                                        <div className="form-group">
                                                            <label for="profession">PAN No</label>
                                                            <div className="fake-input">hello</div>
                                                        </div>
                                                    </div>

                                                    <div className="col-md-4 mb-3">
                                                        <div className="form-group">
                                                            <label for="address">Address 1</label>
                                                            <div className="fake-input">hello</div>
                                                        </div>
                                                    </div>
                                                    <div className="col-md-4 mb-3">
                                                        <div className="form-group">
                                                            <label for="address">Address 2</label>
                                                            <div className="fake-input">hello</div>
                                                       </div>
                                                    </div>
                                                    <div className="col-md-4 mb-3">
                                                        <div className="form-group">
                                                            <label for="location">City</label>
                                                            <div className="fake-input">hello</div>
                                                        </div>
                                                    </div>
                                                    <div className="col-md-4 mb-3">
                                                        <div className="form-group">
                                                            <label for="website1">Postal Code</label>
                                                            <div className="fake-input">hello</div>
                                                        </div>
                                                    </div>
                                                    <div className="col-md-4 mb-3">
                                                        <div className="form-group">
                                                            <label for="website1">Country</label>
                                                            <div className="fake-input">hello</div>
                                                        </div>
                                                    </div>
                                                    <div className="col-md-4 mb-3">
                                                        <div className="form-group">
                                                            <label for="phone">Telephone</label>
                                                            <div className="fake-input">hello</div>
                                                        </div>
                                                    </div>
                                                    <div className="col-md-4 mb-3">
                                                        <div className="form-group">
                                                            <label for="email">Email id </label>
                                                            <div className="fake-input">hello</div>
                                                        </div>
                                                    </div>                                    
                                                    <div className="col-md-4 mb-3">
                                                        <div className="form-group">
                                                            <label for="website1">GST No</label>
                                                            <div className="fake-input">hello</div>
                                                        </div>
                                                    </div>
                                                    <div className="col-md-4 mb-3">
                                                        <div className="form-group">
                                                            <label for="website1">Bank Name</label>
                                                            <div className="fake-input">hello</div>
                                                        </div>
                                                    </div>
                                                    <div className="col-md-4 mb-3">
                                                        <div className="form-group">
                                                            <label for="website1">Bank Account No./ IFSC Code</label>
                                                            <div className="fake-input">hello</div>
                                                        </div>
                                                    </div>
                                                </div> */}
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
            </div>

        </>
    )
}

export default adminProfile;

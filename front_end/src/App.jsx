import React from 'react';
import Layout from './Components/layout';
import Login from './Pages/login';
import ForgotPassword from './Pages/forgotPassword';
import ChangePassword from './Pages/changePassword';

import AdminLayout from './Components/admin/adminLayout';
import AdminDashboard from './Admin_Pages/adminDashboard';
import AdminUser from './Admin_Pages/user';
import AdminAlert from './Admin_Pages/alert';
import AdminContact from './Admin_Pages/contact';
import AdminFranchise from './Admin_Pages/franchiseDetails';
import Profile from './Admin_Pages/adminProfile';
import AdminCmrNdcDetails from './Admin_Pages/cmrNdcDetails';
import AdminKnowledgeCenter from './Admin_Pages/adminKnowledgeCenter';
import KnowldgeGeneral from './Admin_Pages/Knowldge_Center_pages/general';
import KnowldgeSop from './Admin_Pages/Knowldge_Center_pages/sop';
import KnowldgeFranchiseeHelpbook from './Admin_Pages/Knowldge_Center_pages/franchiseeHelpbook';
import KnowldgeTrainingModule from './Admin_Pages/Knowldge_Center_pages/trainingModule';

import Dashboard from './Pages/dashboard';
import Store from './Pages/store';
import Declaration from './Pages/declaration';
import Ledger from './Pages/statements/ledger';
import Commission from './Pages/statements/commission';
import CreditDebit from './Pages/statements/creditdebit';
import TdsCertificates from './Pages/statements/tdsCertificates';
import SecurityDeposit from './Pages/statements/securitydeposit';
import Agreements from './Pages/agreements';
import Support from './Pages/support';
import KnowledgeCenter from './Pages/knowledgeCenter';
import UserGeneral from './Pages/knowledge_center/userGeneral';
import UserSop from './Pages/knowledge_center/userSOP';
import UserTraining from './Pages/knowledge_center/userTraining';
import UserSearchResult from './Pages/knowledge_center/userSearchResult';
import UserFranchisee from './Pages/knowledge_center/userFranchiseeHelpBook';
import { Routes, Route, BrowserRouter } from 'react-router-dom';
import { ToastContainer, Bounce } from "react-toastify";
import 'react-toastify/dist/ReactToastify.css';

function App() {

   return (
      <>
         <BrowserRouter>
            <Routes>
               {/* Common Route*/}
               <Route path='/' element={<Login />} />
               <Route path= "/forgotPassword" element={<ForgotPassword/>} />
                {/* Admin Routes */}
                <Route path='/admin' element={<AdminLayout />}>
                  <Route path="/admin/changePassword" element={<ChangePassword/>}/> 
                  <Route path='/admin/dashboard' element={<AdminDashboard />} />
                  <Route path='/admin/user' element={<AdminUser />} />
                  <Route path='/admin/alert' element={<AdminAlert />} />
                  <Route path='/admin/contact' element={<AdminContact />} />
                  <Route path='/admin/franchise' element={<AdminFranchise />} />
                  <Route path='/admin/profile' element={< Profile/>} />
                  <Route path='/admin/cmr_ndc_details' element={<AdminCmrNdcDetails />} />
                  <Route path='/admin/adminKnowledgeCenter' element={<AdminKnowledgeCenter/>} />
                  <Route path='/admin/adminKnowledgeCenter/general' element={<KnowldgeGeneral/>} />
                  <Route path='/admin/adminKnowledgeCenter/sop' element={<KnowldgeSop/>} />
                  <Route path='/admin/adminKnowledgeCenter/trainingModule' element={<KnowldgeTrainingModule/>} />
                  <Route path='/admin/adminKnowledgeCenter/franchiseeHelpbook' element={<KnowldgeFranchiseeHelpbook/>} />
                </Route>
                {/* User Routes */}
               <Route path='/user' element={<Layout />}>
                  <Route path='/user/dashboard' element={<Dashboard />} />
                  <Route path='/user/store' element={<Store />} />
                  <Route path='/user/declaration' element={<Declaration />} />
                  <Route path='/user/statements/ledger' element={<Ledger />} />
                  <Route path='/user/statements/commission' element={<Commission />} />
                  <Route path='/user/statements/creditdebit' element={<CreditDebit />} />
                  <Route path='/user/statements/tdsCertificates' element={< TdsCertificates />} />
                  <Route path='/user/statements/securitydeposit' element={< SecurityDeposit />} />
                  <Route path='/user/agreements' element={<Agreements />} />
                  <Route path='/user/support' element={<Support />} />
                  <Route path='/user/profile' element={<Profile />} />
                  <Route path='/user/knowledgecenter' element={<KnowledgeCenter />} />
                  <Route path='/user/knowledgecenter/userGeneral' element={<UserGeneral />} />
                  <Route path='/user/knowledgecenter/userSOP' element={<UserSop />} />
                  <Route path='/user/knowledgecenter/userTraining' element={<UserTraining/>} />
                  <Route path='/user/knowledgecenter/userFranchisee' element={<UserFranchisee />} />
                  <Route path='/user/knowledgecenter/userSearchResult' element={<UserSearchResult />} />
               </Route>
            </Routes>
         </BrowserRouter>
         <ToastContainer
            position="top-right"
            autoClose={5000}
            hideProgressBar={false}
            newestOnTop={true}
            closeOnClick={false}
            rtl={false}
            pauseOnFocusLoss
            draggable
            pauseOnHover
            theme="colored"
            transition={Bounce}
         />
      </>
   )
}

export default App
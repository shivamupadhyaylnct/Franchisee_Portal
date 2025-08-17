import React from 'react'
import AdminSidebar from './adminSidebar'
import Footer from '../footer'
import { Outlet } from 'react-router-dom'
import Header from '../header'
import 'react-toastify/dist/ReactToastify.css';
import { ToastContainer } from 'react-toastify'
function adminLayout() {
  return (
    <div className="container-xxl">
      <ToastContainer position="top-right" autoClose={3000} />
        <Header/>
            <div className="main-container" id="container">
                <AdminSidebar/>
                <Outlet/> 
            </div>
        <Footer />
    </div>
  )
}

export default adminLayout

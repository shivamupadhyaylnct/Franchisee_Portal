import React from 'react'
import Header from './header'
import Footer from './footer'
import Sidebar from './sidebar'
import { Outlet } from 'react-router-dom'

function Layout() {
    return (
        <div className="container-xxl">
            <Header />
            <div className="main-container" id="container">
                <Sidebar />
                <Outlet />
            </div>
            <Footer />
        </div>
    )
}

export default Layout
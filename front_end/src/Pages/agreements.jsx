import React from "react";
import comesoon from '../../src/assets/img/comesoon.svg';

function Agreements() {

    return (
        <>
            <div id="content" className="main-content">
                <div className="layout-px-spacing1">
                    <div className="middle-content container-xxl p-0 "
                        style={{
                            color: '#888ea8',
                            height: '100%',
                            fontSize: '0.875rem',
                            background: '#fafafa',
                            backgroundImage: 'linear-gradient(to bottom, #a8edea 0%, #fed6e3 100%)'
                        }}
                    >
                        <div style={{
                            minHeight: '100vh',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            textAlign: 'center',
                            padding: '30px',
                        }}>
                            <img src={comesoon} alt="Coming soon"
                                style={{
                                    maxWidth: '470px',
                                    marginBottom: '50px',
                                }} />
                        </div>

                    </div>
                </div>
            </div >
        </>
    )
}

export default Agreements;
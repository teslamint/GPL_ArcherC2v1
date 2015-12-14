+======================================================================+
|                                                                      |
| Subject   : README for Driver Framework v3.0 Final                   |
| Product   : EIP Driver Framework                                     |
| Date      : 5 Feb, 2009                                              |
|                                                                      |
| File      : README.txt                                               |
|                                                                      |
+======================================================================+

Introduction
------------

This package contains the SafeNet EIP Driver Framework related
documentation and examples.

EIP Driver Framework consists of three interfaces that are mandated by
the EIP Driver Libraries. These interfaces must be implemented for the
environment (HW+OS) that the EIP Driver Libraries will be used in,
according to the Porting Guidelines document.

Driver Framework is composed of the following three APIs:
- Basic Definitions API
- CLib Abstraction API
- Hardware Access API

The "What's New?" section further down in this document gives a quick overview
of the differences between Driver Framework v3.0 and v3.1.


Package Contents
----------------

This package contains the following components:

1) Documentation

README         .\README.txt
Release notes: .\docs\DriverFramework_ReleaseNotes.pdf
Porting Guide: .\docs\EIP_Driver_Framework_Porting_Guide.pdf

2) Example implementation

An example implementation is provided that can be used as a starting
point for a port of each of the three APIs:

.\Basic_Defs\incl\basic_defs.h
.\CLib_Abstraction\incl\clib.h
.\HW_Access_API\incl\hw_access.h
.\HW_Access_API\incl\hw_access_dma.h


What's New since last release?
-----------------------------

The main change to v3.0 RC1 is addition of MASK_n_BITS in 
basic_defs.h, resolving QA package remarks, updating Porting Guide for DMA 
buffer control design pattern.

Added:
- MASK_n_BITS definitions in basic_defs.h

Updated:
- HWPAL_DMAResource_Create

------------------------------------------------------------------------------


<end-of-document>

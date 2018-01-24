# Threat model for gateway

## Overview

This document describes a threat model for an IoT gateway device.
This device bridges between a series of IoT devices on a BLE mesh
network to the great internet.

This figure shows the gateway device, and how it is connected.  The
scope of this document is the device contained within the red box.

![Gateway architecture](gateway-structure.svg)

This system consists of an ARM-based Linux system running, using EMMC
and DRAM.  The system contains a WiFi module that connects to the
user's home network.  In addition, there is a BLE peripheral that
consists of a Cortex v7m MCU that implements the BLE protocol and
communicates with the Linux device over an SPI bus.

The IoT Devices are covered in the [Sensor](sensor.md) document.
Security of the internet is beyond the scope of this document, and
this document will assume all traffic over the WiFi is adversarial.
In addition, this analysis will assume an active adversarial attacker
on the BLE network.

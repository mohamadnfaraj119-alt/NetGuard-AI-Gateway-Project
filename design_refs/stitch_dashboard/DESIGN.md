---
name: Cyber-Sentinel
colors:
  surface: '#111417'
  surface-dim: '#111417'
  surface-bright: '#37393d'
  surface-container-lowest: '#0c0e12'
  surface-container-low: '#191c1f'
  surface-container: '#1d2023'
  surface-container-high: '#282a2e'
  surface-container-highest: '#323539'
  on-surface: '#e1e2e7'
  on-surface-variant: '#b9cacb'
  inverse-surface: '#e1e2e7'
  inverse-on-surface: '#2e3134'
  outline: '#849495'
  outline-variant: '#3a494b'
  surface-tint: '#00dbe7'
  primary: '#e1fdff'
  on-primary: '#00363a'
  primary-container: '#00f2ff'
  on-primary-container: '#006a71'
  inverse-primary: '#00696f'
  secondary: '#ebb2ff'
  on-secondary: '#520072'
  secondary-container: '#b600f8'
  on-secondary-container: '#fff6fc'
  tertiary: '#e4ffd6'
  on-tertiary: '#053900'
  tertiary-container: '#34fc0d'
  on-tertiary-container: '#106f00'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#74f5ff'
  primary-fixed-dim: '#00dbe7'
  on-primary-fixed: '#002022'
  on-primary-fixed-variant: '#004f54'
  secondary-fixed: '#f8d8ff'
  secondary-fixed-dim: '#ebb2ff'
  on-secondary-fixed: '#320047'
  on-secondary-fixed-variant: '#74009f'
  tertiary-fixed: '#79ff5b'
  tertiary-fixed-dim: '#2ae500'
  on-tertiary-fixed: '#022100'
  on-tertiary-fixed-variant: '#095300'
  background: '#111417'
  on-background: '#e1e2e7'
  surface-variant: '#323539'
typography:
  headline-lg:
    fontFamily: Inter
    fontSize: 40px
    fontWeight: '700'
    lineHeight: 48px
    letterSpacing: -0.02em
  headline-lg-mobile:
    fontFamily: Inter
    fontSize: 30px
    fontWeight: '700'
    lineHeight: 36px
    letterSpacing: -0.02em
  headline-md:
    fontFamily: Inter
    fontSize: 24px
    fontWeight: '600'
    lineHeight: 32px
    letterSpacing: -0.01em
  body-md:
    fontFamily: Inter
    fontSize: 16px
    fontWeight: '400'
    lineHeight: 24px
    letterSpacing: 0em
  data-mono:
    fontFamily: JetBrains Mono
    fontSize: 14px
    fontWeight: '500'
    lineHeight: 20px
    letterSpacing: 0em
  label-caps:
    fontFamily: JetBrains Mono
    fontSize: 12px
    fontWeight: '700'
    lineHeight: 16px
    letterSpacing: 0.1em
spacing:
  unit: 4px
  gutter: 24px
  margin-desktop: 40px
  margin-mobile: 16px
  container-max: 1440px
---

## Brand & Style
The design system embodies a high-stakes, technical atmosphere tailored for elite cybersecurity operations. It projects a personality of precision, vigilance, and technological superiority. The target audience includes SOC analysts, security engineers, and CTOs who require immediate clarity amidst complex data.

The visual style is a fusion of **Neon-Brutalism** and **Glassmorphism**. It utilizes a "Dark Mode First" philosophy, where high-vibrancy accents pierce through a deep, ink-black void. The emotional response is one of "command and control"—calculated, futuristic, and urgent. Surfaces are treated as semi-transparent digital HUDs (Heads-Up Displays) floating over a data-rich environment, using glowing borders and light-refractive properties to define hierarchy.

## Colors
The palette is built on a foundation of total darkness to maximize the perceived brightness of the neon accents. 

- **Background**: The base is `#05070a`, a deep ink-black that provides infinite depth.
- **Primary (Electric Cyan)**: Used for active states, primary actions, and secure status. It represents the "Sentinel" presence.
- **Secondary (Neon Magenta)**: Reserved strictly for high-risk alerts, critical vulnerabilities, and destructive actions.
- **Tertiary (Cyber Lime)**: Used for health indicators, successful patches, and "go" signals.
- **Accents**: All accent colors should be applied with an outer glow (bloom effect) to simulate a physical light source on the screen.

## Typography
The system employs a dual-font strategy. **Inter** handles all interface copy and headings for maximum readability and a modern, professional feel. 

**JetBrains Mono** is utilized for all technical data, IP addresses, logs, and system metrics. This distinction helps users subconsciously categorize information: Inter for "Intent" and JetBrains Mono for "Evidence." Labels should often be set in uppercase with increased letter spacing to mimic military-grade instrumentation.

## Layout & Spacing
This design system utilizes a **12-column fluid grid** with a strict 4px baseline rhythm. Padding and margins should always be multiples of 4.

- **Desktop**: 24px gutters with 40px outer margins. Content is organized into "Modules" that span 3, 6, or 12 columns.
- **Mobile**: Grid collapses to 4 columns with 16px margins. 
- **Density**: The layout favors high information density (compact spacing) to allow analysts to see as much data as possible without scrolling. Use "Data Strips" (horizontal rows) for listing threats, with minimal vertical padding.

## Elevation & Depth
Elevation is achieved through **Glassmorphism** and **Light Injection** rather than standard shadows.

1.  **Backdrop**: All floating panels must have a `backdrop-filter: blur(20px)` and a background opacity of 60% using the surface color.
2.  **Gradient Borders**: Instead of flat strokes, use linear-gradient borders (top-left to bottom-right). For primary elements, the gradient transitions from `rgba(0, 242, 255, 0.4)` to `transparent`.
3.  **Colored Glows**: Elements do not cast black shadows. High-priority elements cast a subtle glow of their own accent color (e.g., a Magenta glow for a critical alert card) using `drop-shadow` or `box-shadow` with high spread and low opacity (15-25%).

## Shapes
The shape language is **Sharp and Geometric**. To reinforce the feeling of a rigid, secure system, all primary containers, buttons, and input fields use 0px border-radius. 

Small exceptions are made for inner elements like status pips or toggle switches, which can use a "Soft" (1) setting, but the structural framing of the UI remains strictly rectangular. This evokes a "terminal" or "mainframe" aesthetic.

## Components
- **Buttons**: Primary buttons are solid Electric Cyan with black text. They feature a persistent `0px 0px 15px rgba(0, 242, 255, 0.5)` outer glow. Secondary buttons are "Ghost" style with a gradient border.
- **Status Chips**: Use JetBrains Mono. They should be semi-transparent with a 1px solid border of the status color (Cyan, Magenta, or Lime).
- **Cards**: All cards must use the Glassmorphism specification. Headers within cards should have a subtle 1px bottom border to separate titles from data.
- **Input Fields**: Dark background (`#000000`), sharp corners, and a 1px border that glows Electric Cyan on `:focus`.
- **Threat Gauges**: Circular or linear progress indicators using the Tertiary-to-Secondary color range to visualize risk levels.
- **Data Tables**: Use "Zebra striping" with very low opacity (`rgba(255,255,255,0.02)`) and monospaced values for vertical alignment of numbers.
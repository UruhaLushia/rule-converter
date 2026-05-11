// prettier-ignore
/* eslint-disable */
// @ts-nocheck

import { existsSync } from 'node:fs'
import { join } from 'node:path'
import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)
const __dirname = new URL('.', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1')

const packageName = '@uruhalushia/rule-converter-napi'
const binaryName = 'rule-converter'
const loadErrors = []

function shouldCheckVersion() {
  return process.env.NAPI_RS_ENFORCE_VERSION_CHECK && process.env.NAPI_RS_ENFORCE_VERSION_CHECK !== '0'
}

function requireLocal(tuple) {
  const filename = join(__dirname, `${binaryName}.${tuple}.node`)
  if (!existsSync(filename)) {
    return null
  }
  try {
    return require(filename)
  } catch (err) {
    loadErrors.push(err)
    return null
  }
}

function requirePackage(tuple) {
  const nativePackage = `${packageName}-${tuple}`
  try {
    const binding = require(nativePackage)
    if (shouldCheckVersion() && require(`${nativePackage}/package.json`).version !== require('./package.json').version) {
      throw new Error(
        `Native binding package version mismatch. You can reinstall dependencies to fix this issue.`,
      )
    }
    return binding
  } catch (err) {
    loadErrors.push(err)
    return null
  }
}

function requireBinding(tuple) {
  return requireLocal(tuple) || requirePackage(tuple)
}

function requireLinuxBinding(gnuTuple, muslTuple) {
  if (existsSync('/etc/alpine-release')) {
    return requireBinding(muslTuple) || requireBinding(gnuTuple)
  }
  return requireBinding(gnuTuple) || requireBinding(muslTuple)
}

function requireNative() {
  if (process.env.NAPI_RS_NATIVE_LIBRARY_PATH) {
    try {
      return require(process.env.NAPI_RS_NATIVE_LIBRARY_PATH)
    } catch (err) {
      loadErrors.push(err)
    }
  }

  if (process.platform === 'win32') {
    if (process.arch === 'x64') return requireBinding('win32-x64-msvc')
    if (process.arch === 'arm64') return requireBinding('win32-arm64-msvc')
  } else if (process.platform === 'darwin') {
    if (process.arch === 'x64') return requireBinding('darwin-x64')
    if (process.arch === 'arm64') return requireBinding('darwin-arm64')
  } else if (process.platform === 'linux') {
    if (process.arch === 'x64') return requireLinuxBinding('linux-x64-gnu', 'linux-x64-musl')
    if (process.arch === 'arm64') return requireLinuxBinding('linux-arm64-gnu', 'linux-arm64-musl')
    if (process.arch === 'riscv64') return requireLinuxBinding('linux-riscv64-gnu', 'linux-riscv64-musl')
    if (process.arch === 'loong64') return requireLinuxBinding('linux-loong64-gnu', 'linux-loong64-musl')
  }

  loadErrors.push(new Error(`Unsupported OS or architecture: ${process.platform} ${process.arch}`))
  return null
}

const nativeBinding = requireNative()

if (!nativeBinding) {
  const error = new Error('Failed to load rule-converter native binding')
  error.cause = loadErrors
  throw error
}

export default nativeBinding
export const bufToBuf = nativeBinding.bufToBuf
export const strToBuf = nativeBinding.strToBuf
export const fileToBuf = nativeBinding.fileToBuf
export const bufToStr = nativeBinding.bufToStr
export const strToStr = nativeBinding.strToStr
export const fileToStr = nativeBinding.fileToStr
export const listIndexes = nativeBinding.listIndexes
export const listIndexesFromBuffer = nativeBinding.listIndexesFromBuffer
export const listGeoipCountries = nativeBinding.listGeoipCountries
export const listGeoipCountriesFromBuffer = nativeBinding.listGeoipCountriesFromBuffer
export const listGeoipDatCountries = nativeBinding.listGeoipDatCountries
export const listGeoipDatCountriesFromBuffer = nativeBinding.listGeoipDatCountriesFromBuffer
export const listGeositeCodes = nativeBinding.listGeositeCodes
export const listGeositeCodesFromBuffer = nativeBinding.listGeositeCodesFromBuffer
export const listAsnNumbers = nativeBinding.listAsnNumbers
export const listAsnNumbersFromBuffer = nativeBinding.listAsnNumbersFromBuffer
export const matchBuf = nativeBinding.matchBuf
export const matchStr = nativeBinding.matchStr
export const matchFile = nativeBinding.matchFile

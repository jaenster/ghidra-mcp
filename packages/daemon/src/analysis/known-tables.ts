/**
 * Known function-pointer table registry for cross-platform linking.
 * Shared between the table-linker script and MCP table discovery tool.
 */

export interface TableDef {
  name: string;
  winAddr: string;
  macAddr: string;
  count: number;
  stride: number;
  ptrOffsets: number[];
  macPtrOffsets?: number[];
}

export const KNOWN_TABLES: TableDef[] = [
  {
    name: 'aQuestInitDataExtended (fpQuestInit)',
    winAddr: '00731510',
    macAddr: '003e2170',
    count: 37,
    stride: 24,
    ptrOffsets: [0],
  },
  {
    name: 'ApplicationBootstrapArray (init/shutdown)',
    winAddr: '00706554',
    macAddr: '003e0eb8',
    count: 6,
    stride: 8,
    ptrOffsets: [0, 4],
  },
  {
    name: 'S2C Packet Dispatch (handler/handlerUnit)',
    winAddr: '007114d0',
    macAddr: '003cfe80',
    count: 175,
    stride: 12,
    ptrOffsets: [0, 8],
  },
  {
    name: 'EQUIP BodyLocation Handlers',
    winAddr: '00721e60',
    macAddr: '003d0c5c',
    count: 9,
    stride: 4,
    ptrOffsets: [0],
  },
  {
    name: 'gaPlayerModeCallbacks',
    winAddr: '00732c10',
    macAddr: '003e1c0c',
    count: 20,
    stride: 4,
    ptrOffsets: [0],
  },
  {
    name: 'SKILLCLTDOFUNCS',
    winAddr: '00727ba8',
    macAddr: '00398b30',
    count: 130,
    stride: 4,
    ptrOffsets: [0],
  },
  {
    name: 'SKILLSRVDOFUNCS',
    winAddr: '007322b0',
    macAddr: '003c7ac0',
    count: 152,
    stride: 4,
    ptrOffsets: [0],
  },
  {
    name: 'gapObjectOperateCallbacks',
    winAddr: '00732cec',
    macAddr: '003e17d0',
    count: 10,
    stride: 4,
    ptrOffsets: [0],
  },
  {
    name: 'OBJECTSOPERATEFN',
    winAddr: '00732d18',
    macAddr: '003e180c',
    count: 74,
    stride: 4,
    ptrOffsets: [0],
  },
  {
    name: 'C2S Packet Dispatch (NET_D2GS_SERVER_INCOMING)',
    winAddr: '006e0d18',
    macAddr: '003e1e28',
    count: 103,
    stride: 8,
    ptrOffsets: [0],
  },
  {
    name: 'arrGeneralAiList (init/main/secondary)',
    winAddr: '0073ca18',
    macAddr: '003ba268',
    count: 148,
    stride: 16,
    ptrOffsets: [4, 8, 12],
  },
  {
    name: 'DropHandlerArray',
    winAddr: '006e2260',
    macAddr: '003e0fec',
    count: 21,
    stride: 16,
    ptrOffsets: [0],
  },
  {
    name: 'MISSILESCLTDOFUNCS',
    winAddr: '0072a398',
    macAddr: '003b1b80',
    count: 91,
    stride: 4,
    ptrOffsets: [0],
  },
  {
    name: 'STATESSETFUNC',
    winAddr: '0072a690',
    macAddr: '003b3d58',
    count: 19,
    stride: 4,
    ptrOffsets: [0],
  },
  {
    name: 'STATESREMFUNC',
    winAddr: '0072a710',
    macAddr: '003b3dd4',
    count: 12,
    stride: 4,
    ptrOffsets: [0],
  },
  {
    name: 'gaPropertyFuncTable',
    winAddr: '00745b58',
    macAddr: '003e05e0',
    count: 37,
    stride: 8,
    ptrOffsets: [0],
  },
  {
    name: 'Missiles_CltHitFunc',
    winAddr: '0072a530',
    macAddr: '003b1cf0',
    count: 50,
    stride: 4,
    ptrOffsets: [0],
  },
  {
    name: 'SKILLCLTSTFUNCS',
    winAddr: '00727a90',
    macAddr: '00398a18',
    count: 70,
    stride: 4,
    ptrOffsets: [0],
  },
  {
    name: 'SKILLSRVSTFUNCS',
    winAddr: '00732140',
    macAddr: '003c7954',
    count: 91,
    stride: 4,
    ptrOffsets: [0],
  },
  {
    name: 'MISSILESSRVDOFUNCS',
    winAddr: '0073c768',
    macAddr: '003bad20',
    count: 53,
    stride: 4,
    ptrOffsets: [0],
  },
  {
    name: 'MISSILESSRVHITFUNCS',
    winAddr: '0073c840',
    macAddr: '003badf4',
    count: 71,
    stride: 4,
    ptrOffsets: [0],
  },
  {
    name: 'gaPlayerModeMoveFuncs',
    winAddr: '006e1740',
    macAddr: '003e1c5c',
    count: 40,
    stride: 4,
    ptrOffsets: [0],
  },
];

import tls_client as requests


def GetLoginArkoseToken():
    public_key = "0A1D34FC-659D-4E23-B17B-694DCFCF6A6C"
    session = requests.Session(
        client_identifier="chrome117",
        random_tls_extension_order=True,
    )
    url = f"https://tcr9i.chat.openai.com/fc/gt2/public_key/{public_key}"

    # payload = "bda=eyJjdCI6ImNXcFQwR0xPQnJNaXNmQXRzNlpqUzFKS0RGcjlwVU14SGxoVlRaK1dub2V5RWlaeTNVbWg4WUdSaVRaUk9ENWVNajhxdnUxNU1PRHhURGxpQ3kwQmJuK1JGUG5wcytJSVI2VzltYlBURnVVd1VoN2JKWWtPMUFEZXc1TklPWkFDK1hDb2o5NnVDY0Z3RVlUSFFlakpvZ0FseGFZL0x5Nm9xY1hDQkp5Vys3RmNrdWJJSituU1BJMDVJY3ZzYWo2eExNNkxZY2tsZ2F0MW9JMDNsOSt6LzVwZ09KQlB0ZFdScFZjbXZYL2Nvbng0UktBbk5ndkM0TENQUGxRWnNZNnlXWmEwRW1IdDc1QXBEK3Y1TnFQdXhqalV4OENVandyUVhVTDBDaDNUbkJteVpJb2FVa3hiWHd3UHM4OE8wb2RiM0JaSVZMZ3JjczhZK1pBZkYzNk94U2kzVXBNdzN5SUplU1UvNHQ5Vlk5amZtMG1YUmxxQjNIaGREdVdleWp4Z1FzK0N1TWI1emY3Z2pzUXBNV2w0VGlQclE2QUVnVTk0OEE5ZkRYK1Q2YU5BUU5jT0FiRVBnZW5HZWVQeldXUHFwa0xaWkNocms5NFBDVWpyQnpydjhTeXZLOEcwTkFuZEZ5SVJ1M1A0QVNaMi9aRjE5cU8xOHNMRzJDMnVMRmNROHg0UXVoTzVvWk9QTmE2NGhkMmN3YmxEZ3V4cWZhVDhqaHJpbXE5dWhzdDdKQ2pqYVoveVYzSlJMUDVxOWMyQjNlVGE5Q3FoVEZlVmxReDZDMW56U2pFSzVKa1Y1b01LdXJmc29YWUJqSzg0bFEvWU94MXBveTI2SVlQOUJ6cVNtdkNwWkt2M1Y4bHBpNDVqUVJCNGp4bzZtNHdtZDJaOXA3Vk43RklMcWEwYU5OWnpOS0FXWnNtRkZvK3MrM1p5TlZOT21Nbkg0akdVZnlLMXJSQnJUc2Q1NFduUzF5bG5PVnhVVHI3ZHJGNXNlaXBOckJoN2MvUER4S2pCcStHVzRaVEpYdzlBVFZodURLdnkxdTBsK3dwZm80R201ekcwTUVOcnRLRHUxczFicm9UQjNNRm1zbTc4clZ2dTZxKzJkTXZ1clVJZ1NId3ZzMy9Kck9wNU12cUZrcVJ4cFpLRGx0Z0JMMDFNM0l4T1ZtK2ZnVTRNcjNNZmorQnQ2akQxVUdVM3JDa2thZVU2QUlmUmJVVkJGNUp6S3lWZm5IcGRTNUloLzlMcGp5QVBUb253Wk9LZ2RHaTRYSUgzNkxVZ0NEMFNsbWNvY0NUZDg4ZGZJdzc1MWpINERnLzJCblF1OUY5S0MwM3IxYXo0NzFoZVQ1WWU3ODNHYzUvZXkydUhKYU9vSjAxQnRNTG14cEJxL1NJc3FXRXdyeWUrU0h0YWF4c2JrWlo0amwveXlaSjNCN0Rtb0paUW9oNnRxb25GbWhFWlgrNGpPb2pmeG9oRVE1VG9EU3czR2xvWWlQSjFtRkVjbXY4UGdPY0ZOZ2xqYjhvTjNwNWVzQ2ZEN2IzN0J0TkdYanJXRHltOGY4VTJQalBXcGRyTTNvaEVmeHBVclU4djY3S0dkZGtUSUw3ZHhPMi9MRU5oMG1hR2JST1hFcmxpclZZcmxaQ0tPOWVmRWp1MGVwcEtja0h1U0htNDFQM3I5aEkvTWtnbFRWaGZXdWNKZ3ZzWmU0WEZKRnMvK3pyR3RhOVV3ek5Sc2Y5aWpvQkFzdElZK3lIdEVOaFFpb0V2VkJkTEx1TkxLd1dGampHN3R5U1VqeUV2N0Q4NXJDai9KSFlPT3B1RXRKK2pQRUx6NHhHcmtDUFo1S1dFeGhRRkVGOWlDRGJIbUlSeUxLVDFFeXNnT3hHcmljclovWGs1VUNSQ0sxcUhmT0JiOXIvSWNvbnVFRHEyWi8zQUh6dTlXZTdFOUc1dU0rSXdtRlJGanQ0UHF3LzUzUVZ5Z1ZleGlhNE1rVGlWQWRCVFk4Sjlqc2E5SWVVcit4NnBtYUFqS2krd0hzb1JQLytwcEZYQUc5NjFDV2l5TUtYZlFibXVUd2xmeVdNZ3BEanV5eGpnMkJIdTQ4aC8wUmxXcVFYRjlCbTB3aFJ5YVpldnhRWUdkR20yMUlSNDgxdUFNYVBGTnNhZCtBZGdaZk1UQWgvWlNhZlE5a0ZRTGwwUEZORWN2Nms4czJiN2dQM2g0cmUyeW1QQ294bC9ROThkWnB4cDRiTEJtVDZDcVFhNkt4NU9tU2pGb0JKaXI2LzVHK09ZUk1aZkZNQ2lLS211cFBPV3lyQ2lOZG5hVGdpckExaEppOHVBekUvaE9xUnNDdmtEK2hUTWxrM3pjaWtXbHRzdXVKbVh5RmpNRlhPV0lBMlkvZmRFUU1PZk1rZEl4M0JLZGZKVHI2cHdBcXA5Tm5zaDI0c1c4T0F1WGRTZUtCTHJwSTVOVTF1T2dobXFwc0tIMUpkc1VPQ3ZkVmNEK3Q0VFhqSFR5MXNNVzlBUjhVTVhYZzJjditZQ3M0UTd3UHJBWWJoM2MwYk8wOTBPYXN6YmdvYkoyazUyM3ZpbktjQ3JmRGxUcmlZcEI0ZFNCbTl4amFOT1dLcG5vVkhlRlhoZGZZYXFESFFsdU1admU4cHluYkoycUVEWWNmdXN1Y09hQnVJYVREb0d2R2xreHMwVnBPRSs1aEhmZUpaMjFYVnVyazB6KytWaFRJN3RnOUhIa3FvSWdZUnN2VURlck1QL0c4cno3V1BrRmxMMUFjWHE1NVJIUmFEYWlBOFlrMkpxSmpNcU1VTnZiWDlKRUtSbjlVVzREWHh6WjgreXo4cEpZZDZXdDdNRHNxbjdCNytWSkJJTjZMZ1V4ZUVuMTd2U2JDZVBMVGcxK3poVWprRmxEUmtybGFEdlN6OGdGS0dlalNzbnNQeldPeDFVeTZEd05VRCtDQmlBVEtyaUpGUXdsRUtMZjNCSlRZYVppMmV6Nmt6ZVRmWVZVdkV6MnlSeXZVelFBRTVRTy8rNlJBWWVJaTJ0U1NKcXFGT2F5cVp5S3M4K2RGMWlHanFVcTByUWhNbllQdTBHYTN6UFlqNFkwTVZtcm9OWUVsbE94Zlp2VlBqSU9jWmg5TzluN01lWnoxMFIxRkhFWHpoU3BwRGVwRlBuMDQxelhiKzdSMFZzZzAwU21FcVUwdll6OTVRQUt1STlNTHZzcjgrT0FQRjBTNktTS1BOL0lYN1VwQnBRY2JMck02YUE1RjJuZTJndXZKZk5MNXBHUlgrSjk2ZGhXZ0FJUlpqNVFSRkEvdXB2Qm90c1g2U2RKMXZkZDV0Z0VMVlRmUnM2aC9NYmZBcTBqTC80ZEk5QjEremJtcEtEYWkxZktxNXVDcVpMbkJrWm5JbHREWm9CSkNaWE9LMDFIaGpVa3ZEZ1hPS1JJQ1IydC9pOG9XOVpuSXUzdjJUeEcyR253ZjFHTFhrS0JZbGxIY0U4TS9jTGw0Y2ZBMFc1N01raHdoVnNiVDlubmsxd1Q0SVVESURUYlA0NHFTT29aNXdGWW5lcFl6S0VpRXE3RWlNMC9ZaWdoUzI1STgxSDlpS1U1THNaU2psNHFSSzF3RFhFenRZQ3Vnb0d5V2xMdmlreWl3dndWYllZaHI1TW9tRDJTR2xmMWdqZGszMG1RUGg0N0pDaFZkWHVPRDhiVS9oSXNFc2JiT01nYmZ3eERzZkZuWWRMN0ozMkpwbUFzRVg0emJLbjhFKzJiV3hpY0oyQnFQa0tYRzA2OTk1M01Xa0ZLRGh5eFczZkozSFE5c09SQnM4L21ScUowQkxiY2x2RldQVWw5ekE0YlRxaWZpeEJpbElUVnVpOCtYeTBJYlpZVTJWQWs5akMxdEpXOEZwZkt6SHhaMmZqU1J5MHhRQmdZQ3F3MjRGQ0piOWpSaVJmYzY1ZEwxdWpFWThVazZNUFNKM0hIeW1QeVRKNk93MDREdWgwK0tUSERMdExERlNhOERtU3NCN1ZHdlo4cFQ3V1c5N0QyYkJCZ3YwSEVuQk1zejJES2ljWExIdzBXUjV4TllrQk5YRXdtc1FXdTRIQm14dWh0cmVOS2tZaEgzZ1k5cEhKZUpmWEFBUkUxMkdPU1JpaTlCVGlSem15bGpXSUNqWXJMWmlVZnkyZUtZTlY1STc3L2hUN3d1Vm9ueXBCZ3VYTkVuNlBRYmdrMkxxN0dsY0JpOEJyOFFEYzdvK1pBNm1EZTBKSHp4UjhxckVKSjZOaXNBUDNHVWxyWXNRVVl3TENmL0MzZk04d0tFanpFdFlPa3dDeUNJT0taOXI0UFVuZ2dpbFIvMFZaSDQwcGgxRDFpZ0llbUl6VmpnV0greHVaUXpuN3Y1K2FicnBpWnZsWTZRNGE3RExNTTZ3MkU1MGNkY0RBdlpXdE5jbXZpLzAyZU1HMmIzSWF3UU5keCtyT2hZK1pnZ1d5Zi9SSEhqRUZya2VKckNHdExzaHpqMEtISGRRL3Rkelc5RnRLZ3Y4VFowVnc4eExGQVd0cmZ0dDVPUEVvTWpTMnBjUmdjSzZJQWczRDF3WTRBcXdQbTkwN01uZHBoUHQ4Y2tlY3FRUENNbGJtaXJNZ0ZjOXFUTDByVXNvNHRpdkZXM05hMnp5eGgxdlZHb3l0L1FaTVRFZ1VIN3VwZk9sWWlGS1ZrckxQWGFIQ1FSdEFRdzdTQUpXYlFzOEJxWVUwaTJNLzNzRDIzZ24rZUxqV3VQd1d5djRNMFRtdXkxRmcxOEM2YmN5Tlg4aGNXak94bVZWWG56M015b0JQeFBwY0N3SlpEaURZWW9YaDRKTG9CSk1yWWo5NzQ0YVRZcFVmcXJHV0FWWUQ4YVdLcmRVRnJVSHJYS0huSnY5OUdodjVwOXZjMmdOUGFZMG5LYkY2UzVlR0FBR0hQWXpNelkxNzBpM0tpYjJUVHErUlUvZkhwT2cyUWlZdlZqUmhDUUxwRDYwYURLTmZvUFRFVFQwenhZYmQ0YUE2eGhMN3JCVFo2ODR0QlFueEYzL2ZEbkV1eGN5WEthS3ROL3lEd2JibE1BaEtYUEJQdTNtTWkrMktLK2VNRXV3cEZYdDAyNHBNVGo1WlI3SlllYTNEMjlBVU91YWZXbUNTNkY1dThhSjFlTk1SRHB5OGZYajE0eHlkR1JSempEK1YrL1Fpb0FnUUUwYjJNWm1KRmpFWkxwb1BhcHhCcXpIMnlDbzhTV1FYOWY2ejlhWnc5aGxYTExuRXhPLzEwcU9YWHg0d01SL29QSnp2ekJuajJRU3hvUjFsUTN5WmVBYzd2VlZnNG1OT0pzYUpmNGs1a2FiQ01rZndsSnlDOTBmS0FZVkZKU0t0Y2ZhZytQczVoUW9NL0VIZ29vcUk2YUFjZWdxaDRNb3FEbmVmeEVhZ3NEMkR5MnE4cVRISEIrR2JkTTg1UWZ1UmlEYndybWloclhUTlJSQk5ydFVIRi8xRFpBaHhlcVVLOC9hOGJHdFhjeW1tRyt3R3p4dHlnenBSZkZlWEt2QXJJTWExNlpUWmdzOHRUTXE3aEVLeVNhTk9JUEJBYms0L3FvVE5vTU5XdCtDVGdob3RBMnNBTlpnZUNXZlVseFlZZFJvSUM2TmlZY2RmdGk2TzVLVGFPdUNWamtEQlNXMUNuaDN0MWpYdGZuMmJPUW96MkVzRkpGTkU5OUsxZHBlTTRDMmFCLzRTK2pkeWJ4YkRRTjFKaUR2ZStCaW9nNUFzU3ladnc3a2piZ01pdXNOZW1oNWZzRTB3bldtcFVEVGMzUGRuVlo0cWYwSHZtNk9OQUJweTNXaTVIcE5tb2Y5MHBTVHVGRlJUdCtybmtnd2x3U3dubnZFT2RQVXIrSCszYmZNZ28yNXNKZEhOVWJncmRXbnZQaFY3L2Z1ZEVJZitRV3p4RlF1Vm5CNzlvK2RrV2cybUdSN0lqdmlzVXJCNmFZdG8zS1laTmtZZXRKZ0gxS1p5ZGlzVW4rNUVxaXptelRXbk5sdmpZUjg3cFZ0WUZiaURDVlVlbTZ1WG9EbkNZVmRLWVorVHhEdG9UaEl6cld4ajdTZk5FUGR2OU9BVVYrVHZEQkFDUC93eVVJNkZURThHQ1drbE5vdUtmc1pQTUlaMUVaeVFXSEhPRmVwb2sydjB4eDllWFp4eEgxOEh3b3prQllQV0w0Skd2dXFML2kvZElzQUpvQk80bFo0dUVMZURDUG45MG9hOXRGLzhLSUpmR1M3NHpaZFVnS0lXR2hTVHMzN3NBeW1sNVpzakJ4YUFtd0J6T2lTTG1veExlK2FzN2hDbVNDSkR5Y3hybk1Sa092c2xoeVNMMU8rcGdVUWhDbStxSlhaSWg1ZlZjYXRHbm1kRjdJS1JOdjAySm8xd2NwWjBqTC91dk5UTE5pQUNNVDZObUVabndNWWFwTUlCNUMyT0w5K0NuZHFLbGE3a01ydDFzYU5MSjZLUUt0NXpGcGtCeEd0NjVVSEVBalp5ZE53ZFA3djBJY2tjNitQOXRrRGJFSE1ndk9RMjJzZW1GM3FrU0E2cDFvdFluUUp6b0ZPQ1V1enBOVXpnb1hiZk1VdzFRWEFHWEFVWXhVWnRFeWNjODlXR2dtb0lib2N4ZWlESDE4N1IyYlplKzd1QnFWeVUrQytwTmk2V3A2U00ydTZrYjNNSW52cHpJaHNBMXVZM0tKY1JFZ1duOC9QdjBXRDdSN3VnZmZ1SjR2Rm1yUG5YdUxqL2JKZDY5c3JqOEtoZUFDemVOT3hVRWtCRTZhRDB5M1kxZTFtelE5T2pVN0JaQzQvaUN4WU5ya3UvV2RTRi9tN3FoWU5BM20vcUNOenY2QzZ2L3VXempGWDVWQTZIanRubGpJUm9kWHZrSHdUeVJuRERySkllc0VjUlJaaEtZYlU0bWdQa1QzK01zOHA1V09xRmdseExUVU1OQnhZVG45N2V3ZTdzK0F2Zmt5QjJHcGhDTFpINm9VV2Z0VlJjWml3ay9SWHFKMnVCVUxHNjVtUTRMalAvdE9NRXgybHcrdVlvSll3QU9qWDZicVRzRmxOUjFOT2xydXlVMjAvVWxxSUpZTDliTnY5VDdHemxTRkQxWjZHdDdjZ20wNkZHZXBLUWsrZG9PR1VlMTZUc0tEbzlLR2FzdlJ5QlNqOHlLL2RxK2RiQVVzMm9hQ1JjSnJKeXNQZjRLVHNPVU52VzQ4bEFkSGtKeTZzNlpNUDFqRjFpWVozbFJWbHZwMlZKMkQyUVhtK3FWaUtndVZSVGN3NnRicXBKN3ZoMjZXc2VZV1ozcWFzcitmdURPeHBGR0x0OXlUaTRJb3lBV2cxbTJmaEsybUxLZXJWRlQ4OUtad05nM2UzMU4wZlFRZjlJZmZUTXlwMCtpNnZqQklUZ0IwVmt4cnhmc0ZpVlRIQy9tMTlRcjZIYlNHQTNEZkpRK1BsZU5zd2YwSzNkRTJsUUtvbm4zV2pRMFhQRXZCa3NJMmpzVWZDZnAwNnBxUlBkNWRXV3ZWcWduM3lRY1dJQWthd1d6L1lxN2t1TmZJbm9ydDdtN2cwTmZpQUpSYXFlallFSnhoOGw5M1FUVDZNK0Y3b3JJRnVMbHhZVXY2Z0MvNEpybE03N2ZiVmZWWlVEVllqKzRZVGNHc0FHN01pbkg0RTVFWVlkR0ZNRlJKYThPVjhoM1VFWEZMM20rVDNybDkxVGk3YUdLaE9RWVpIUmJ0eEptOU5DYkRqZjhBVTdFcDRmV0FXaUhDNmtrSCt5dDlEc2pQclpJa2lTczBETzU2M0UvUjFXa3dYWC9JUkhBTlZSZGhHdm5pT0E2Y0JBSG45eFZZaFdOTmNCa0poejdUOEhsZU1vQzYwV0E1T2xzTjVYL3J0QnQ4QlhRQVNKNE9EZzl2Y3k1Y0FyR2ZZbzR0ZkJsUHQ5TWoxUlBoSktIVkpieVdGRU9OZ3owdUM0aEhnSlNKU3VtVkRUcVBIWUNrLzNCQit3enV3dnQ0clpaVDhJTW82TFZ3bEpOeVpZZjdic0xaTUxHN0RWQ09OZklXYmg2VVVmT2tFOTg1YWRkZ3ZlcVlZb3BLOFcxTkp4SC9LU1RYRERkTVplclFJWmFKc0FVUFRBUzRDRDY2WWZROFA3TGxZOUs2Mm1vWmUrZ3lYd2dqQlVsaWhIUFBPeUpTK01WN3hRRy9UaFhraURCLysyaVBuZWJKZDZtc1Z1Vm5qcHdzMmhORFYrRU94T2x5MmRRY3lQQVJMZVFjdjMxRmh1SkZrVEJPRzZoY01IK3MxbndWSzNCMmgyVlNYREhQaHRlMnYrS2N6c21oYnYweDdPTytQdXFNdll5WUJhOG1DYVVJWnMwMDhaVjhYV2hqcWNHZEJMQTArQVZHNHZvOFRseW1za3VDdmlCR0dKYktGelJXT242cS9SQ1poYnFKd0R2V0Q4R3BCUSt5YWVtNUxIYjBzdFFDb2o5cFoycFBXcDR2WUZRRzUzZGlwdzg3TFUyWjZweDh1czlaNEV2YlA5RExSem5CeG1lQVFnUTA1Z3ljYWk5NTk3WHFiZk9ETFB5Qkl2WDYyRXV1Z3luKzBjaTArTndxa0x2NkhQOWE4YVRhMXFhRDBSaDRPbi9jKzc2WFF5ZDgxMU5iRldkaTJQTkd5R3daeVpyYllhUEN4UnlzanZYNnZXZitkMVd1SG03bGxRSEY5Y1NianI0VmhMN0NSRXBUTTE1cFEwaHJsV3l2YklBTEhVY1lLZHNJNGJ1b0RjQ0oyYUdQeWFPMkpzZVIwUm1Zek1hdDV6MmxFaytpYUtYUEJoK0V2T2dpclM4RXZwRVdHRFRzbXRzNzN3Z2pEVXBseGFSVFhKQUxrQlVGbkltUXhFMitHR3JhRDhFby84bDl1QU1KQWNYSWQzSTkyeW9GQjA2aUZpVVpZNE9rSG52UlF5ekNSR3Z1cjAyaVg0Wk5JSnE0YlhWL0twY21LbEtBVmFkT004KzZJbTYvM3h2bGk4dXo0elkwU3JNeHFxZmIxWlBEM0t0U1NPSStIVmFqRDA5OUczeUF3ZitpZlBLWWtySXFGclZ2RTdSRlZrVnp0WERrMURwUnBldWFpUXRUM1JMV2Mwd2tGQWM3MFJRb0o4OTFaZGVxY2xSTVI0N2Z3M2JiUE9yUGo2dDRzU09CUWFqWHljUHp3VUpycXM0dTdjRHJFS042TzYrb0F4MkJGelppckVMdVp2YXBydGZaanQrM2djeEJLUHJid1Rzc2xTTGlrWjJ6YUE0Mk5lTWh5M0I2dDg1L3NVeDFQWUlYUGtUMTRxNkM1QWlZWVhGTW8rbmNnVi8rdXIvM3ZpWVZvV3lrY1hqRElBdFN4YlppSHpNenRqMVRYNWFFeWw5TkJ5QlJuaDdEV2F3SExwNGlNajd4bHNGWDNBMDlucVNwVGhpQnp6TDNjTWlyYmx4OVg0MVU1SnRPYTFnSDhSSmx5Q0VJeG4zOGhLMWlST0xhaGhXcFlhWkt2WCIsIml2IjoiNWY1NGRmMWFjNTFkOWI2Yjg1M2JkN2JhNmU1MDFjYWEiLCJzIjoiYzY5NzhkNjBiZDM4NDVkOSJ9&public_key=0A1D34FC-659D-4E23-B17B-694DCFCF6A6C&site=https://auth0.openai.com&userbrowser=Mozilla/5.0%20(Windows%20NT%2010.0%3B%20Win64%3B%20x64)%20AppleWebKit/537.36%20(KHTML%2C%20like%20Gecko)%20Chrome/117.0.0.0%20Safari/537.36&capi_version=1.5.5&capi_mode=lightbox&style_theme=default&rnd=0.7074844518109926"
    # TODO:
    payload = {
        "bda": "eyJjdCI6ImNXcFQwR0xPQnJNaXNmQXRzNlpqUzFKS0RGcjlwVU14SGxoVlRaK1dub2V5RWlaeTNVbWg4WUdSaVRaUk9ENWVNajhxdnUxNU1PRHhURGxpQ3kwQmJuK1JGUG5wcytJSVI2VzltYlBURnVVd1VoN2JKWWtPMUFEZXc1TklPWkFDK1hDb2o5NnVDY0Z3RVlUSFFlakpvZ0FseGFZL0x5Nm9xY1hDQkp5Vys3RmNrdWJJSituU1BJMDVJY3ZzYWo2eExNNkxZY2tsZ2F0MW9JMDNsOSt6LzVwZ09KQlB0ZFdScFZjbXZYL2Nvbng0UktBbk5ndkM0TENQUGxRWnNZNnlXWmEwRW1IdDc1QXBEK3Y1TnFQdXhqalV4OENVandyUVhVTDBDaDNUbkJteVpJb2FVa3hiWHd3UHM4OE8wb2RiM0JaSVZMZ3JjczhZK1pBZkYzNk94U2kzVXBNdzN5SUplU1UvNHQ5Vlk5amZtMG1YUmxxQjNIaGREdVdleWp4Z1FzK0N1TWI1emY3Z2pzUXBNV2w0VGlQclE2QUVnVTk0OEE5ZkRYK1Q2YU5BUU5jT0FiRVBnZW5HZWVQeldXUHFwa0xaWkNocms5NFBDVWpyQnpydjhTeXZLOEcwTkFuZEZ5SVJ1M1A0QVNaMi9aRjE5cU8xOHNMRzJDMnVMRmNROHg0UXVoTzVvWk9QTmE2NGhkMmN3YmxEZ3V4cWZhVDhqaHJpbXE5dWhzdDdKQ2pqYVoveVYzSlJMUDVxOWMyQjNlVGE5Q3FoVEZlVmxReDZDMW56U2pFSzVKa1Y1b01LdXJmc29YWUJqSzg0bFEvWU94MXBveTI2SVlQOUJ6cVNtdkNwWkt2M1Y4bHBpNDVqUVJCNGp4bzZtNHdtZDJaOXA3Vk43RklMcWEwYU5OWnpOS0FXWnNtRkZvK3MrM1p5TlZOT21Nbkg0akdVZnlLMXJSQnJUc2Q1NFduUzF5bG5PVnhVVHI3ZHJGNXNlaXBOckJoN2MvUER4S2pCcStHVzRaVEpYdzlBVFZodURLdnkxdTBsK3dwZm80R201ekcwTUVOcnRLRHUxczFicm9UQjNNRm1zbTc4clZ2dTZxKzJkTXZ1clVJZ1NId3ZzMy9Kck9wNU12cUZrcVJ4cFpLRGx0Z0JMMDFNM0l4T1ZtK2ZnVTRNcjNNZmorQnQ2akQxVUdVM3JDa2thZVU2QUlmUmJVVkJGNUp6S3lWZm5IcGRTNUloLzlMcGp5QVBUb253Wk9LZ2RHaTRYSUgzNkxVZ0NEMFNsbWNvY0NUZDg4ZGZJdzc1MWpINERnLzJCblF1OUY5S0MwM3IxYXo0NzFoZVQ1WWU3ODNHYzUvZXkydUhKYU9vSjAxQnRNTG14cEJxL1NJc3FXRXdyeWUrU0h0YWF4c2JrWlo0amwveXlaSjNCN0Rtb0paUW9oNnRxb25GbWhFWlgrNGpPb2pmeG9oRVE1VG9EU3czR2xvWWlQSjFtRkVjbXY4UGdPY0ZOZ2xqYjhvTjNwNWVzQ2ZEN2IzN0J0TkdYanJXRHltOGY4VTJQalBXcGRyTTNvaEVmeHBVclU4djY3S0dkZGtUSUw3ZHhPMi9MRU5oMG1hR2JST1hFcmxpclZZcmxaQ0tPOWVmRWp1MGVwcEtja0h1U0htNDFQM3I5aEkvTWtnbFRWaGZXdWNKZ3ZzWmU0WEZKRnMvK3pyR3RhOVV3ek5Sc2Y5aWpvQkFzdElZK3lIdEVOaFFpb0V2VkJkTEx1TkxLd1dGampHN3R5U1VqeUV2N0Q4NXJDai9KSFlPT3B1RXRKK2pQRUx6NHhHcmtDUFo1S1dFeGhRRkVGOWlDRGJIbUlSeUxLVDFFeXNnT3hHcmljclovWGs1VUNSQ0sxcUhmT0JiOXIvSWNvbnVFRHEyWi8zQUh6dTlXZTdFOUc1dU0rSXdtRlJGanQ0UHF3LzUzUVZ5Z1ZleGlhNE1rVGlWQWRCVFk4Sjlqc2E5SWVVcit4NnBtYUFqS2krd0hzb1JQLytwcEZYQUc5NjFDV2l5TUtYZlFibXVUd2xmeVdNZ3BEanV5eGpnMkJIdTQ4aC8wUmxXcVFYRjlCbTB3aFJ5YVpldnhRWUdkR20yMUlSNDgxdUFNYVBGTnNhZCtBZGdaZk1UQWgvWlNhZlE5a0ZRTGwwUEZORWN2Nms4czJiN2dQM2g0cmUyeW1QQ294bC9ROThkWnB4cDRiTEJtVDZDcVFhNkt4NU9tU2pGb0JKaXI2LzVHK09ZUk1aZkZNQ2lLS211cFBPV3lyQ2lOZG5hVGdpckExaEppOHVBekUvaE9xUnNDdmtEK2hUTWxrM3pjaWtXbHRzdXVKbVh5RmpNRlhPV0lBMlkvZmRFUU1PZk1rZEl4M0JLZGZKVHI2cHdBcXA5Tm5zaDI0c1c4T0F1WGRTZUtCTHJwSTVOVTF1T2dobXFwc0tIMUpkc1VPQ3ZkVmNEK3Q0VFhqSFR5MXNNVzlBUjhVTVhYZzJjditZQ3M0UTd3UHJBWWJoM2MwYk8wOTBPYXN6YmdvYkoyazUyM3ZpbktjQ3JmRGxUcmlZcEI0ZFNCbTl4amFOT1dLcG5vVkhlRlhoZGZZYXFESFFsdU1admU4cHluYkoycUVEWWNmdXN1Y09hQnVJYVREb0d2R2xreHMwVnBPRSs1aEhmZUpaMjFYVnVyazB6KytWaFRJN3RnOUhIa3FvSWdZUnN2VURlck1QL0c4cno3V1BrRmxMMUFjWHE1NVJIUmFEYWlBOFlrMkpxSmpNcU1VTnZiWDlKRUtSbjlVVzREWHh6WjgreXo4cEpZZDZXdDdNRHNxbjdCNytWSkJJTjZMZ1V4ZUVuMTd2U2JDZVBMVGcxK3poVWprRmxEUmtybGFEdlN6OGdGS0dlalNzbnNQeldPeDFVeTZEd05VRCtDQmlBVEtyaUpGUXdsRUtMZjNCSlRZYVppMmV6Nmt6ZVRmWVZVdkV6MnlSeXZVelFBRTVRTy8rNlJBWWVJaTJ0U1NKcXFGT2F5cVp5S3M4K2RGMWlHanFVcTByUWhNbllQdTBHYTN6UFlqNFkwTVZtcm9OWUVsbE94Zlp2VlBqSU9jWmg5TzluN01lWnoxMFIxRkhFWHpoU3BwRGVwRlBuMDQxelhiKzdSMFZzZzAwU21FcVUwdll6OTVRQUt1STlNTHZzcjgrT0FQRjBTNktTS1BOL0lYN1VwQnBRY2JMck02YUE1RjJuZTJndXZKZk5MNXBHUlgrSjk2ZGhXZ0FJUlpqNVFSRkEvdXB2Qm90c1g2U2RKMXZkZDV0Z0VMVlRmUnM2aC9NYmZBcTBqTC80ZEk5QjEremJtcEtEYWkxZktxNXVDcVpMbkJrWm5JbHREWm9CSkNaWE9LMDFIaGpVa3ZEZ1hPS1JJQ1IydC9pOG9XOVpuSXUzdjJUeEcyR253ZjFHTFhrS0JZbGxIY0U4TS9jTGw0Y2ZBMFc1N01raHdoVnNiVDlubmsxd1Q0SVVESURUYlA0NHFTT29aNXdGWW5lcFl6S0VpRXE3RWlNMC9ZaWdoUzI1STgxSDlpS1U1THNaU2psNHFSSzF3RFhFenRZQ3Vnb0d5V2xMdmlreWl3dndWYllZaHI1TW9tRDJTR2xmMWdqZGszMG1RUGg0N0pDaFZkWHVPRDhiVS9oSXNFc2JiT01nYmZ3eERzZkZuWWRMN0ozMkpwbUFzRVg0emJLbjhFKzJiV3hpY0oyQnFQa0tYRzA2OTk1M01Xa0ZLRGh5eFczZkozSFE5c09SQnM4L21ScUowQkxiY2x2RldQVWw5ekE0YlRxaWZpeEJpbElUVnVpOCtYeTBJYlpZVTJWQWs5akMxdEpXOEZwZkt6SHhaMmZqU1J5MHhRQmdZQ3F3MjRGQ0piOWpSaVJmYzY1ZEwxdWpFWThVazZNUFNKM0hIeW1QeVRKNk93MDREdWgwK0tUSERMdExERlNhOERtU3NCN1ZHdlo4cFQ3V1c5N0QyYkJCZ3YwSEVuQk1zejJES2ljWExIdzBXUjV4TllrQk5YRXdtc1FXdTRIQm14dWh0cmVOS2tZaEgzZ1k5cEhKZUpmWEFBUkUxMkdPU1JpaTlCVGlSem15bGpXSUNqWXJMWmlVZnkyZUtZTlY1STc3L2hUN3d1Vm9ueXBCZ3VYTkVuNlBRYmdrMkxxN0dsY0JpOEJyOFFEYzdvK1pBNm1EZTBKSHp4UjhxckVKSjZOaXNBUDNHVWxyWXNRVVl3TENmL0MzZk04d0tFanpFdFlPa3dDeUNJT0taOXI0UFVuZ2dpbFIvMFZaSDQwcGgxRDFpZ0llbUl6VmpnV0greHVaUXpuN3Y1K2FicnBpWnZsWTZRNGE3RExNTTZ3MkU1MGNkY0RBdlpXdE5jbXZpLzAyZU1HMmIzSWF3UU5keCtyT2hZK1pnZ1d5Zi9SSEhqRUZya2VKckNHdExzaHpqMEtISGRRL3Rkelc5RnRLZ3Y4VFowVnc4eExGQVd0cmZ0dDVPUEVvTWpTMnBjUmdjSzZJQWczRDF3WTRBcXdQbTkwN01uZHBoUHQ4Y2tlY3FRUENNbGJtaXJNZ0ZjOXFUTDByVXNvNHRpdkZXM05hMnp5eGgxdlZHb3l0L1FaTVRFZ1VIN3VwZk9sWWlGS1ZrckxQWGFIQ1FSdEFRdzdTQUpXYlFzOEJxWVUwaTJNLzNzRDIzZ24rZUxqV3VQd1d5djRNMFRtdXkxRmcxOEM2YmN5Tlg4aGNXak94bVZWWG56M015b0JQeFBwY0N3SlpEaURZWW9YaDRKTG9CSk1yWWo5NzQ0YVRZcFVmcXJHV0FWWUQ4YVdLcmRVRnJVSHJYS0huSnY5OUdodjVwOXZjMmdOUGFZMG5LYkY2UzVlR0FBR0hQWXpNelkxNzBpM0tpYjJUVHErUlUvZkhwT2cyUWlZdlZqUmhDUUxwRDYwYURLTmZvUFRFVFQwenhZYmQ0YUE2eGhMN3JCVFo2ODR0QlFueEYzL2ZEbkV1eGN5WEthS3ROL3lEd2JibE1BaEtYUEJQdTNtTWkrMktLK2VNRXV3cEZYdDAyNHBNVGo1WlI3SlllYTNEMjlBVU91YWZXbUNTNkY1dThhSjFlTk1SRHB5OGZYajE0eHlkR1JSempEK1YrL1Fpb0FnUUUwYjJNWm1KRmpFWkxwb1BhcHhCcXpIMnlDbzhTV1FYOWY2ejlhWnc5aGxYTExuRXhPLzEwcU9YWHg0d01SL29QSnp2ekJuajJRU3hvUjFsUTN5WmVBYzd2VlZnNG1OT0pzYUpmNGs1a2FiQ01rZndsSnlDOTBmS0FZVkZKU0t0Y2ZhZytQczVoUW9NL0VIZ29vcUk2YUFjZWdxaDRNb3FEbmVmeEVhZ3NEMkR5MnE4cVRISEIrR2JkTTg1UWZ1UmlEYndybWloclhUTlJSQk5ydFVIRi8xRFpBaHhlcVVLOC9hOGJHdFhjeW1tRyt3R3p4dHlnenBSZkZlWEt2QXJJTWExNlpUWmdzOHRUTXE3aEVLeVNhTk9JUEJBYms0L3FvVE5vTU5XdCtDVGdob3RBMnNBTlpnZUNXZlVseFlZZFJvSUM2TmlZY2RmdGk2TzVLVGFPdUNWamtEQlNXMUNuaDN0MWpYdGZuMmJPUW96MkVzRkpGTkU5OUsxZHBlTTRDMmFCLzRTK2pkeWJ4YkRRTjFKaUR2ZStCaW9nNUFzU3ladnc3a2piZ01pdXNOZW1oNWZzRTB3bldtcFVEVGMzUGRuVlo0cWYwSHZtNk9OQUJweTNXaTVIcE5tb2Y5MHBTVHVGRlJUdCtybmtnd2x3U3dubnZFT2RQVXIrSCszYmZNZ28yNXNKZEhOVWJncmRXbnZQaFY3L2Z1ZEVJZitRV3p4RlF1Vm5CNzlvK2RrV2cybUdSN0lqdmlzVXJCNmFZdG8zS1laTmtZZXRKZ0gxS1p5ZGlzVW4rNUVxaXptelRXbk5sdmpZUjg3cFZ0WUZiaURDVlVlbTZ1WG9EbkNZVmRLWVorVHhEdG9UaEl6cld4ajdTZk5FUGR2OU9BVVYrVHZEQkFDUC93eVVJNkZURThHQ1drbE5vdUtmc1pQTUlaMUVaeVFXSEhPRmVwb2sydjB4eDllWFp4eEgxOEh3b3prQllQV0w0Skd2dXFML2kvZElzQUpvQk80bFo0dUVMZURDUG45MG9hOXRGLzhLSUpmR1M3NHpaZFVnS0lXR2hTVHMzN3NBeW1sNVpzakJ4YUFtd0J6T2lTTG1veExlK2FzN2hDbVNDSkR5Y3hybk1Sa092c2xoeVNMMU8rcGdVUWhDbStxSlhaSWg1ZlZjYXRHbm1kRjdJS1JOdjAySm8xd2NwWjBqTC91dk5UTE5pQUNNVDZObUVabndNWWFwTUlCNUMyT0w5K0NuZHFLbGE3a01ydDFzYU5MSjZLUUt0NXpGcGtCeEd0NjVVSEVBalp5ZE53ZFA3djBJY2tjNitQOXRrRGJFSE1ndk9RMjJzZW1GM3FrU0E2cDFvdFluUUp6b0ZPQ1V1enBOVXpnb1hiZk1VdzFRWEFHWEFVWXhVWnRFeWNjODlXR2dtb0lib2N4ZWlESDE4N1IyYlplKzd1QnFWeVUrQytwTmk2V3A2U00ydTZrYjNNSW52cHpJaHNBMXVZM0tKY1JFZ1duOC9QdjBXRDdSN3VnZmZ1SjR2Rm1yUG5YdUxqL2JKZDY5c3JqOEtoZUFDemVOT3hVRWtCRTZhRDB5M1kxZTFtelE5T2pVN0JaQzQvaUN4WU5ya3UvV2RTRi9tN3FoWU5BM20vcUNOenY2QzZ2L3VXempGWDVWQTZIanRubGpJUm9kWHZrSHdUeVJuRERySkllc0VjUlJaaEtZYlU0bWdQa1QzK01zOHA1V09xRmdseExUVU1OQnhZVG45N2V3ZTdzK0F2Zmt5QjJHcGhDTFpINm9VV2Z0VlJjWml3ay9SWHFKMnVCVUxHNjVtUTRMalAvdE9NRXgybHcrdVlvSll3QU9qWDZicVRzRmxOUjFOT2xydXlVMjAvVWxxSUpZTDliTnY5VDdHemxTRkQxWjZHdDdjZ20wNkZHZXBLUWsrZG9PR1VlMTZUc0tEbzlLR2FzdlJ5QlNqOHlLL2RxK2RiQVVzMm9hQ1JjSnJKeXNQZjRLVHNPVU52VzQ4bEFkSGtKeTZzNlpNUDFqRjFpWVozbFJWbHZwMlZKMkQyUVhtK3FWaUtndVZSVGN3NnRicXBKN3ZoMjZXc2VZV1ozcWFzcitmdURPeHBGR0x0OXlUaTRJb3lBV2cxbTJmaEsybUxLZXJWRlQ4OUtad05nM2UzMU4wZlFRZjlJZmZUTXlwMCtpNnZqQklUZ0IwVmt4cnhmc0ZpVlRIQy9tMTlRcjZIYlNHQTNEZkpRK1BsZU5zd2YwSzNkRTJsUUtvbm4zV2pRMFhQRXZCa3NJMmpzVWZDZnAwNnBxUlBkNWRXV3ZWcWduM3lRY1dJQWthd1d6L1lxN2t1TmZJbm9ydDdtN2cwTmZpQUpSYXFlallFSnhoOGw5M1FUVDZNK0Y3b3JJRnVMbHhZVXY2Z0MvNEpybE03N2ZiVmZWWlVEVllqKzRZVGNHc0FHN01pbkg0RTVFWVlkR0ZNRlJKYThPVjhoM1VFWEZMM20rVDNybDkxVGk3YUdLaE9RWVpIUmJ0eEptOU5DYkRqZjhBVTdFcDRmV0FXaUhDNmtrSCt5dDlEc2pQclpJa2lTczBETzU2M0UvUjFXa3dYWC9JUkhBTlZSZGhHdm5pT0E2Y0JBSG45eFZZaFdOTmNCa0poejdUOEhsZU1vQzYwV0E1T2xzTjVYL3J0QnQ4QlhRQVNKNE9EZzl2Y3k1Y0FyR2ZZbzR0ZkJsUHQ5TWoxUlBoSktIVkpieVdGRU9OZ3owdUM0aEhnSlNKU3VtVkRUcVBIWUNrLzNCQit3enV3dnQ0clpaVDhJTW82TFZ3bEpOeVpZZjdic0xaTUxHN0RWQ09OZklXYmg2VVVmT2tFOTg1YWRkZ3ZlcVlZb3BLOFcxTkp4SC9LU1RYRERkTVplclFJWmFKc0FVUFRBUzRDRDY2WWZROFA3TGxZOUs2Mm1vWmUrZ3lYd2dqQlVsaWhIUFBPeUpTK01WN3hRRy9UaFhraURCLysyaVBuZWJKZDZtc1Z1Vm5qcHdzMmhORFYrRU94T2x5MmRRY3lQQVJMZVFjdjMxRmh1SkZrVEJPRzZoY01IK3MxbndWSzNCMmgyVlNYREhQaHRlMnYrS2N6c21oYnYweDdPTytQdXFNdll5WUJhOG1DYVVJWnMwMDhaVjhYV2hqcWNHZEJMQTArQVZHNHZvOFRseW1za3VDdmlCR0dKYktGelJXT242cS9SQ1poYnFKd0R2V0Q4R3BCUSt5YWVtNUxIYjBzdFFDb2o5cFoycFBXcDR2WUZRRzUzZGlwdzg3TFUyWjZweDh1czlaNEV2YlA5RExSem5CeG1lQVFnUTA1Z3ljYWk5NTk3WHFiZk9ETFB5Qkl2WDYyRXV1Z3luKzBjaTArTndxa0x2NkhQOWE4YVRhMXFhRDBSaDRPbi9jKzc2WFF5ZDgxMU5iRldkaTJQTkd5R3daeVpyYllhUEN4UnlzanZYNnZXZitkMVd1SG03bGxRSEY5Y1NianI0VmhMN0NSRXBUTTE1cFEwaHJsV3l2YklBTEhVY1lLZHNJNGJ1b0RjQ0oyYUdQeWFPMkpzZVIwUm1Zek1hdDV6MmxFaytpYUtYUEJoK0V2T2dpclM4RXZwRVdHRFRzbXRzNzN3Z2pEVXBseGFSVFhKQUxrQlVGbkltUXhFMitHR3JhRDhFby84bDl1QU1KQWNYSWQzSTkyeW9GQjA2aUZpVVpZNE9rSG52UlF5ekNSR3Z1cjAyaVg0Wk5JSnE0YlhWL0twY21LbEtBVmFkT004KzZJbTYvM3h2bGk4dXo0elkwU3JNeHFxZmIxWlBEM0t0U1NPSStIVmFqRDA5OUczeUF3ZitpZlBLWWtySXFGclZ2RTdSRlZrVnp0WERrMURwUnBldWFpUXRUM1JMV2Mwd2tGQWM3MFJRb0o4OTFaZGVxY2xSTVI0N2Z3M2JiUE9yUGo2dDRzU09CUWFqWHljUHp3VUpycXM0dTdjRHJFS042TzYrb0F4MkJGelppckVMdVp2YXBydGZaanQrM2djeEJLUHJid1Rzc2xTTGlrWjJ6YUE0Mk5lTWh5M0I2dDg1L3NVeDFQWUlYUGtUMTRxNkM1QWlZWVhGTW8rbmNnVi8rdXIvM3ZpWVZvV3lrY1hqRElBdFN4YlppSHpNenRqMVRYNWFFeWw5TkJ5QlJuaDdEV2F3SExwNGlNajd4bHNGWDNBMDlucVNwVGhpQnp6TDNjTWlyYmx4OVg0MVU1SnRPYTFnSDhSSmx5Q0VJeG4zOGhLMWlST0xhaGhXcFlhWkt2WCIsIml2IjoiNWY1NGRmMWFjNTFkOWI2Yjg1M2JkN2JhNmU1MDFjYWEiLCJzIjoiYzY5NzhkNjBiZDM4NDVkOSJ9",
        "public_key": public_key, "site": "https://auth0.openai.com",
        "userbrowser": "Mozilla/5.0%20(Windows%20NT%2010.0%3B%20Win64%3B%20x64)%20AppleWebKit/537.36%20(KHTML%2C%20like%20Gecko)%20Chrome/117.0.0.0%20Safari/537.36",
        "capi_version": "1.5.5", "capi_mode": "lightbox", "style_theme": "default", "rnd": "0.7074844518109926"}

    headers = {
        'authority': 'tcr9i.chat.openai.com',
        'accept': '*/*',
        'accept-language': 'ar,en-US;q=0.9,en;q=0.8',
        'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'cookie': '_cfuvid=bBazTResL4RMt9nS_c3HIWeiH2F9xXvnftYgTBhyRJQ-1696222545650-0-604800000; __cf_bm=NdJWAyGOm1mxnnUWSK_ybiJqihM0KOKGSlap7pXMIvk-1696222581-0-AZpDEaiV1ATDArdkMH7+OJpSXzhe6XRyxOTIUrFSo83aRX93BlyzwdRVfijXbdA5s3W6PQIPafOTfuLEX0wsbnk=; _cfuvid=M5Cv4oW4c.eQdzNMvUgZCO9L5.Zq3t72pzrLbmz58GU-1696222581873-0-604800000; cf_clearance=vjQyw5ks4uQmXgcm6wI5hFooclzWMQCBStJtG8iddfg-1696222582-0-1-e0659aa7.535c9cda.d7e418d7-0.2.1696222582',
        'dnt': '1',
        'origin': 'https://tcr9i.chat.openai.com',
        'referer': 'https://tcr9i.chat.openai.com/v2/1.5.5/enforcement.fbfc14b0d793c6ef8359e0e4b4a91f67.html',
        'sec-ch-ua': '"Google Chrome";v="117", "Not;A=Brand";v="8", "Chromium";v="117"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36'
    }

    response = session.post(url, headers=headers, data=payload)

    token = response.json().get("token")
    print(response.json())
    return token


d = GetLoginArkoseToken()
print(d)

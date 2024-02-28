#include "KDrv.h"

extern std::unique_ptr<KDrvImplement> CreateKDrvimplementObject();

std::shared_ptr<KDrv> CreateKDrvObject()
{
    return std::make_shared<KDrv>(std::move(CreateKDrvimplementObject()));
}
